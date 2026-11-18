"""Stand-ins for the outside world in worker tests: a TLS IMAP server that
speaks the subset of IMAP4rev1 imaplib uses (with LOGIN and AUTHENTICATE
XOAUTH2), and OAuth token endpoints for Microsoft and Google."""

from __future__ import annotations

import base64
import datetime as dt
import ipaddress
import json
import re
import socketserver
import ssl
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.x509.oid import NameOID


def make_tls_files(tmp_path) -> tuple[str, str]:
    """A self-signed certificate for 127.0.0.1 / localhost; returns (cert, key)
    paths. The cert doubles as the CA file a test trusts (SSL_CERT_FILE)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return str(cert_path), str(key_path)


class FakeImapServer:
    """Messages live in self.messages (uid -> bytes) in INBOX. Accepts
    LOGIN user/password, or AUTHENTICATE XOAUTH2 with user and a token in
    self.tokens."""

    def __init__(self, cert: str, key: str, user: str = "reports@example.com", password: str = "imap-password"):
        self.user = user
        self.password = password
        self.tokens: set[str] = set()
        self.messages: dict[int, bytes] = {}
        self.seen: set[int] = set()
        self.moved: dict[int, str] = {}
        self.logins: list[str] = []  # "password" / "xoauth2" per successful sign-in
        self.on_fetch = None  # hook(uid) called before a message is returned
        outer = self

        class Handler(socketserver.StreamRequestHandler):
            def send(self, line: str | bytes) -> None:
                data = line if isinstance(line, bytes) else line.encode()
                self.wfile.write(data + b"\r\n")
                self.wfile.flush()

            def handle(self) -> None:
                self.send("* OK [CAPABILITY IMAP4rev1 AUTH=XOAUTH2 MOVE] ready")
                authed = False
                while True:
                    raw = self.rfile.readline()
                    if not raw:
                        return
                    line = raw.decode(errors="replace").rstrip("\r\n")
                    tag, _, rest = line.partition(" ")
                    cmd, _, args = rest.partition(" ")
                    cmd = cmd.upper()
                    if cmd == "CAPABILITY":
                        self.send("* CAPABILITY IMAP4rev1 AUTH=XOAUTH2 MOVE")
                        self.send(f"{tag} OK done")
                    elif cmd == "LOGIN":
                        user, password = [p.strip('"') for p in re.findall(r'"(?:[^"\\]|\\.)*"|\S+', args)][:2]
                        if user == outer.user and password == outer.password:
                            authed = True
                            outer.logins.append("password")
                            self.send(f"{tag} OK logged in")
                        else:
                            self.send(f"{tag} NO [AUTHENTICATIONFAILED] Invalid credentials")
                    elif cmd == "AUTHENTICATE":
                        self.send("+ ")
                        response = base64.b64decode(self.rfile.readline().strip() or b"").decode(errors="replace")
                        m = re.fullmatch(r"user=([^\x01]*)\x01auth=Bearer ([^\x01]*)\x01\x01", response)
                        if m and m.group(1) == outer.user and m.group(2) in outer.tokens:
                            authed = True
                            outer.logins.append("xoauth2")
                            self.send(f"{tag} OK authenticated")
                        else:
                            self.send(f"{tag} NO AUTHENTICATE failed.")
                    elif not authed and cmd not in ("LOGOUT",):
                        self.send(f"{tag} NO not authenticated")
                    elif cmd in ("SELECT", "EXAMINE"):
                        self.send(f"* {len(outer.messages)} EXISTS")
                        self.send(f"{tag} OK [READ-WRITE] selected")
                    elif cmd == "CREATE":
                        self.send(f"{tag} OK created")
                    elif cmd == "UID":
                        self.uid(tag, args)
                    elif cmd in ("EXPUNGE", "CLOSE", "NOOP"):
                        self.send(f"{tag} OK done")
                    elif cmd == "LOGOUT":
                        self.send("* BYE")
                        self.send(f"{tag} OK bye")
                        return
                    else:
                        self.send(f"{tag} BAD unknown command")

            def uid(self, tag: str, args: str) -> None:
                sub, _, rest = args.partition(" ")
                sub = sub.upper()
                if sub == "SEARCH":
                    uids = [u for u in sorted(outer.messages) if u not in outer.seen and u not in outer.moved]
                    self.send("* SEARCH " + " ".join(str(u) for u in uids))
                    self.send(f"{tag} OK search done")
                    return
                uid = int(rest.split(" ")[0])
                if sub == "FETCH":
                    if outer.on_fetch:
                        outer.on_fetch(uid)
                    body = outer.messages[uid]
                    self.wfile.write(b"* %d FETCH (UID %d BODY[] {%d}\r\n" % (uid, uid, len(body)) + body + b")\r\n")
                    self.send(f"{tag} OK fetch done")
                elif sub == "STORE":
                    if "Seen" in rest:
                        outer.seen.add(uid)
                    self.send(f"{tag} OK store done")
                elif sub in ("MOVE", "COPY"):
                    outer.moved[uid] = rest.split(" ", 1)[1].strip('"')
                    self.send(f"{tag} OK moved")
                else:
                    self.send(f"{tag} BAD")

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(cert, key)

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

            def get_request(self):
                sock, addr = super().get_request()
                return context.wrap_socket(sock, server_side=True), addr

        self.server = Server(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class FakeTokenEndpoint:
    """POST /microsoft and /google. Records requests; issues `token` when the
    credentials match, else an OAuth error."""

    def __init__(self, token: str = "fake-access-token", client_id: str = "app-id", client_secret: str = "client-secret", google_public_key=None):
        self.token = token
        self.client_id = client_id
        self.client_secret = client_secret
        self.google_public_key = google_public_key
        self.requests: list[dict] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # quiet
                pass

            def reply(self, status: int, payload: dict) -> None:
                body = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                form = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()))
                path = urllib.parse.urlsplit(self.path).path
                outer.requests.append({"path": self.path, **form})
                if path == "/microsoft":
                    if form.get("grant_type") != "client_credentials" or form.get("scope") != "https://outlook.office365.com/.default":
                        return self.reply(400, {"error": "invalid_request"})
                    if form.get("client_id") != outer.client_id or form.get("client_secret") != outer.client_secret:
                        return self.reply(401, {"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided.\nTrace ID: x"})
                    return self.reply(200, {"access_token": outer.token, "token_type": "Bearer", "expires_in": 3599})
                if path == "/google":
                    if form.get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer":
                        return self.reply(400, {"error": "unsupported_grant_type"})
                    try:
                        head, claims, sig = form["assertion"].split(".")
                        pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
                        outer.google_public_key.verify(
                            base64.urlsafe_b64decode(pad(sig)), f"{head}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256()
                        )
                        outer.requests[-1]["claims"] = json.loads(base64.urlsafe_b64decode(pad(claims)))
                    except Exception:  # noqa: BLE001
                        return self.reply(400, {"error": "invalid_grant", "error_description": "Invalid JWT Signature."})
                    return self.reply(200, {"access_token": outer.token, "token_type": "Bearer", "expires_in": 3599})
                self.reply(404, {"error": "not_found"})

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
