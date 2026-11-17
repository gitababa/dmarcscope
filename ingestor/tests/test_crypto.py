"""The secret envelope, against vectors shared with the web app
(tests/unit/envelope.test.ts reads the same file)."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from ingestor.crypto import EnvelopeError, decrypt, encrypt, secrets_from_env

VECTORS = json.loads((Path(__file__).resolve().parents[2] / "tests" / "vectors" / "envelope.json").read_text())
S = VECTORS["secrets"]
CASES = VECTORS["cases"]


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def raw(envelope: str) -> bytes:
    return base64.urlsafe_b64decode(envelope + "=" * (-len(envelope) % 4))


def fails(code: str, **kwargs) -> None:
    with pytest.raises(EnvelopeError) as exc:
        decrypt(**kwargs)
    assert exc.value.code == code


def test_vectors_come_from_both_languages():
    assert {c["producer"] for c in CASES} == {"typescript", "python"}


@pytest.mark.parametrize("case", CASES, ids=lambda c: f"{c['producer']}-{c['context']}")
def test_decrypts_every_vector(case):
    out = decrypt(secrets=[S["current"], S["previous"]], purpose=case["purpose"], context=case["context"], envelope=case["envelope"])
    assert out.plaintext == case["plaintext"]
    assert out.key_index == (0 if case["secret"] == "current" else 1)


@pytest.mark.parametrize("case", CASES, ids=lambda c: f"{c['producer']}-{c['context']}")
def test_reencrypts_every_vector_to_the_same_bytes(case):
    again = encrypt(
        secret=S[case["secret"]],
        purpose=case["purpose"],
        context=case["context"],
        plaintext=case["plaintext"],
        nonce=bytes.fromhex(case["nonce"]),
    )
    assert again == case["envelope"]


def test_wrong_key_fails_loudly():
    for case in CASES:
        fails("unknown_key", secrets=[S["other"]], purpose=case["purpose"], context=case["context"], envelope=case["envelope"])


def test_truncated_envelope_fails_loudly():
    case = CASES[0]
    full = raw(case["envelope"])
    for length in (1, 5, 17, 32):
        fails("malformed", secrets=[S["current"]], purpose=case["purpose"], context=case["context"], envelope=b64(full[:length]))
    fails("auth_failed", secrets=[S["current"]], purpose=case["purpose"], context=case["context"], envelope=b64(full[:-1]))
    fails("malformed", secrets=[S["current"]], purpose=case["purpose"], context=case["context"], envelope="")


def test_every_flipped_bit_fails_loudly():
    case = CASES[0]
    full = raw(case["envelope"])
    for i in range(len(full)):
        bad = bytearray(full)
        bad[i] ^= 0x01
        expected = "version" if i == 0 else "unknown_key" if i < 5 else "auth_failed"
        fails(expected, secrets=[S["current"]], purpose=case["purpose"], context=case["context"], envelope=b64(bytes(bad)))


def test_envelope_is_bound_to_its_record_and_purpose():
    case = CASES[0]
    fails("auth_failed", secrets=[S["current"]], purpose=case["purpose"], context="other.setting", envelope=case["envelope"])
    fails("auth_failed", secrets=[S["current"]], purpose="totp", context=case["context"], envelope=case["envelope"])


def test_garbage_and_missing_keys():
    fails("malformed", secrets=[S["current"]], purpose="setting", context="x", envelope="not base64!")
    fails("no_key", secrets=[], purpose="setting", context="x", envelope=CASES[0]["envelope"])
    with pytest.raises(EnvelopeError):
        encrypt(secret="short", purpose="setting", context="x", plaintext="y")


def test_secrets_from_env():
    assert secrets_from_env({"APP_SECRET": S["current"]}) == [S["current"]]
    assert secrets_from_env({"APP_SECRET": S["current"], "APP_SECRET_PREVIOUS": S["previous"]}) == [S["current"], S["previous"]]
    with pytest.raises(EnvelopeError):
        secrets_from_env({})
    with pytest.raises(EnvelopeError):
        secrets_from_env({"APP_SECRET": S["current"], "APP_SECRET_PREVIOUS": "short"})
