"""Access tokens for mailboxes that sign in with OAuth (docs/mail.md,
"Mailbox kinds").

Microsoft 365: client-credentials grant, scope https://outlook.office365.com/.default,
with the application's service principal given FullAccess to the one mailbox.

Google Workspace: a service account with domain-wide delegation; an RS256 JWT
(iss = service account, sub = the mailbox, scope https://mail.google.com/)
exchanged with the jwt-bearer grant.

The token endpoints are fixed here, never taken from configuration: a
service-account key's "token_uri" is ignored, so a key file cannot send the
signed assertion anywhere else. Error messages never contain the secret.
"""

from __future__ import annotations

import base64
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

MICROSOFT_TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
MICROSOFT_SCOPE = "https://outlook.office365.com/.default"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_SCOPE = "https://mail.google.com/"
TIMEOUT_SECONDS = 30

# A tenant is a GUID or a verified domain name; nothing that could change the
# URL path.
_TENANT = re.compile(r"^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)$")


class TokenError(Exception):
    """The provider refused to issue a token. The message is safe to show."""


@dataclass
class Token:
    value: str
    expires_at: float


def _post_form(url: str, fields: dict[str, str]) -> dict:
    body = urllib.parse.urlencode(fields).encode()
    request = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310 - fixed https endpoints
            return json.loads(response.read(1_000_000) or b"{}")
    except urllib.error.HTTPError as e:
        # The provider's own error code and description (e.g. invalid_client,
        # unauthorized_client): never the request, which holds the secret.
        try:
            payload = json.loads(e.read(100_000) or b"{}")
        except ValueError:
            payload = {}
        code = str(payload.get("error") or f"HTTP {e.code}")[:100]
        description = str(payload.get("error_description") or "").splitlines()[0][:300] if payload.get("error_description") else ""
        raise TokenError(f"{code}{': ' + description if description else ''}") from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise TokenError(f"token endpoint unreachable: {type(e).__name__}") from None


def microsoft_token(tenant: str, client_id: str, client_secret: str, *, url: str | None = None) -> Token:
    if not _TENANT.match(tenant or ""):
        raise TokenError("tenant must be the tenant ID (a GUID) or a domain name")
    payload = _post_form(
        url or MICROSOFT_TOKEN_URL.format(tenant=tenant),
        {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret, "scope": MICROSOFT_SCOPE},
    )
    return _token(payload)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def google_assertion(key: dict, mailbox: str, now: float | None = None) -> str:
    """The signed JWT for the jwt-bearer grant."""
    email = key.get("client_email")
    pem = key.get("private_key")
    if not isinstance(email, str) or not isinstance(pem, str) or key.get("type") != "service_account":
        raise TokenError("the key is not a Google service-account key (JSON with type, client_email and private_key)")
    try:
        private_key = serialization.load_pem_private_key(pem.encode(), password=None)
    except (ValueError, TypeError):
        raise TokenError("the service-account key's private_key cannot be read") from None
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TokenError("the service-account key must be an RSA key")
    issued = int(now if now is not None else time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    if isinstance(key.get("private_key_id"), str):
        header["kid"] = key["private_key_id"]
    claims = {"iss": email, "sub": mailbox, "scope": GOOGLE_SCOPE, "aud": GOOGLE_TOKEN_URL, "iat": issued, "exp": issued + 3600}
    signing_input = f"{_b64url(json.dumps(header, separators=(',', ':')).encode())}.{_b64url(json.dumps(claims, separators=(',', ':')).encode())}"
    signature = private_key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{_b64url(signature)}"


def google_token(key_json: str, mailbox: str, *, url: str | None = None) -> Token:
    try:
        key = json.loads(key_json)
    except ValueError:
        raise TokenError("the service-account key is not valid JSON") from None
    if not isinstance(key, dict):
        raise TokenError("the service-account key is not a JSON object")
    payload = _post_form(
        url or GOOGLE_TOKEN_URL,
        {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": google_assertion(key, mailbox)},
    )
    return _token(payload)


def _token(payload: dict) -> Token:
    value = payload.get("access_token")
    if not isinstance(value, str) or not value:
        raise TokenError("the provider answered without an access token")
    try:
        lifetime = int(payload.get("expires_in", 3600))
    except (TypeError, ValueError):
        lifetime = 3600
    return Token(value=value, expires_at=time.time() + max(60, lifetime))


def xoauth2(user: str, token: str) -> bytes:
    """SASL XOAUTH2 initial response (before base64; imaplib encodes it)."""
    return f"user={user}\x01auth=Bearer {token}\x01\x01".encode()
