"""Encrypted envelopes for secrets stored in the database.

Byte-for-byte the same format as lib/envelope.mjs in the web app (see the
description there); both test suites decrypt tests/vectors/envelope.json.
The worker uses it to read credentials an administrator saved in the panel.

Decryption never falls back: a wrong key, a truncated or altered envelope or
an unknown version raises EnvelopeError.
"""

from __future__ import annotations

import base64
import os
import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VERSION = 1
_HEADER = 5
_NONCE = 12
_TAG = 16
_MIN_SECRET = 32
_LABEL = re.compile(r"^[a-z0-9._:-]{1,100}$")
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")


class EnvelopeError(ValueError):
    """The value cannot be decrypted. The message never contains secrets."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _check_secret(secret: str | None, name: str = "APP_SECRET") -> str:
    if not isinstance(secret, str) or len(secret) < _MIN_SECRET:
        raise EnvelopeError("no_key", f"{name} must be set to at least {_MIN_SECRET} random characters.")
    return secret


def _hkdf(secret: str, info: str, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=b"dmarcscope", info=info.encode()).derive(
        secret.encode()
    )


def key_id(secret: str) -> bytes:
    return _hkdf(_check_secret(secret), "dmarcscope/key-id/v1", 4)


def _purpose_key(secret: str, purpose: str) -> bytes:
    return _hkdf(secret, f"dmarcscope/secret/v1/{purpose}", 32)


def _check_label(value: str, name: str) -> None:
    if not isinstance(value, str) or not _LABEL.match(value):
        raise EnvelopeError("malformed", f"{name} must be a short identifier")


def _aad(header: bytes, purpose: str, context: str) -> bytes:
    return header + f"{purpose}\0{context}".encode()


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def encrypt(*, secret: str, purpose: str, context: str, plaintext: str, nonce: bytes | None = None) -> str:
    _check_secret(secret)
    _check_label(purpose, "purpose")
    _check_label(context, "context")
    iv = nonce if nonce is not None else os.urandom(_NONCE)
    if len(iv) != _NONCE:
        raise EnvelopeError("malformed", "nonce must be 12 bytes")
    header = bytes([VERSION]) + key_id(secret)
    body = AESGCM(_purpose_key(secret, purpose)).encrypt(iv, plaintext.encode(), _aad(header, purpose, context))
    return _b64encode(header + iv + body)


@dataclass(frozen=True)
class Decrypted:
    plaintext: str
    key_index: int  # 0: APP_SECRET, 1: APP_SECRET_PREVIOUS


def decrypt(*, secrets: list[str | None], purpose: str, context: str, envelope: str) -> Decrypted:
    _check_label(purpose, "purpose")
    _check_label(context, "context")
    if not isinstance(envelope, str) or not _B64URL.match(envelope):
        raise EnvelopeError("malformed", "Encrypted value is not base64url text")
    raw = _b64decode(envelope)
    if len(raw) < _HEADER + _NONCE + _TAG:
        raise EnvelopeError("malformed", "Encrypted value is truncated")
    if raw[0] != VERSION:
        raise EnvelopeError("version", f"Encrypted value has unknown format version {raw[0]}")
    header, kid = raw[:_HEADER], raw[1:_HEADER]

    usable = [s for s in secrets if isinstance(s, str) and s]
    if not usable:
        _check_secret(None)
    index = next((i for i, s in enumerate(usable) if key_id(_check_secret(s)) == kid), -1)
    if index == -1:
        raise EnvelopeError(
            "unknown_key",
            "Encrypted value was written under a different APP_SECRET (set APP_SECRET_PREVIOUS to the old one)",
        )
    iv, body = raw[_HEADER : _HEADER + _NONCE], raw[_HEADER + _NONCE :]
    try:
        out = AESGCM(_purpose_key(usable[index], purpose)).decrypt(iv, body, _aad(header, purpose, context))
    except InvalidTag:
        raise EnvelopeError(
            "auth_failed", "Encrypted value failed its integrity check (altered, or bound to another record)"
        ) from None
    return Decrypted(plaintext=out.decode(), key_index=index)


def secrets_from_env(env: dict[str, str] | None = None) -> list[str]:
    """APP_SECRET, then APP_SECRET_PREVIOUS when set."""
    env = dict(os.environ) if env is None else env
    current = _check_secret(env.get("APP_SECRET"))
    previous = env.get("APP_SECRET_PREVIOUS") or ""
    return [current, _check_secret(previous, "APP_SECRET_PREVIOUS")] if previous else [current]
