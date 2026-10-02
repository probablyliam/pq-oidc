"""Unit tests for the Python verifier, plus the cross-language checks.

The interop tests read tokens minted by Node.js (jose, native ML-DSA) from the
file named in INTEROP_FIXTURES and write a Python-signed token to INTEROP_OUT
for Node.js to verify. `npm run interop` wires both directions together.
"""

import json
import os
import secrets
import time

import pytest

from pq_jwt import (
    TokenRejected,
    akp_public_jwk,
    b64url_decode,
    b64url_encode,
    ml_dsa_private_key_from_seed,
    sign_ml_dsa_jwt,
    verify_id_token,
)

ISSUER = "https://login.example"
AUDIENCE = "pq-app"


def claims(**overrides):
    now = int(time.time())
    return {"iss": ISSUER, "aud": AUDIENCE, "sub": "alice", "iat": now, "exp": now + 300, **overrides}


@pytest.fixture(scope="module")
def provider():
    key = ml_dsa_private_key_from_seed("ML-DSA-65", secrets.token_bytes(32))
    return key, {"keys": [akp_public_jwk(key, "ML-DSA-65", "pq-1")]}


def verify(token, jwks, **overrides):
    options = {"issuer": ISSUER, "audience": AUDIENCE, "algorithms": ["ML-DSA-65", "ES256"], **overrides}
    return verify_id_token(token, jwks, **options)


def rejection(token, jwks, **overrides):
    with pytest.raises(TokenRejected) as info:
        verify(token, jwks, **overrides)
    return info.value.code


def test_accepts_a_valid_ml_dsa_65_token(provider):
    key, jwks = provider
    token = sign_ml_dsa_jwt(key, "ML-DSA-65", "pq-1", claims())
    assert verify(token, jwks).claims["sub"] == "alice"
    assert len(b64url_decode(token.split(".")[2])) == 3309  # FIPS 204 signature size


def test_legacy_allowlist_refuses_post_quantum_tokens(provider):
    key, jwks = provider
    token = sign_ml_dsa_jwt(key, "ML-DSA-65", "pq-1", claims())
    assert rejection(token, jwks, algorithms=["ES256"]) == "alg-not-allowed"


def test_rejects_edited_claims(provider):
    key, jwks = provider
    header, _, signature = sign_ml_dsa_jwt(key, "ML-DSA-65", "pq-1", claims()).split(".")
    forged = b64url_encode(json.dumps(claims(sub="admin")).encode())
    assert rejection(f"{header}.{forged}.{signature}", jwks) == "bad-signature"


def test_rejects_unsigned_tokens(provider):
    _, jwks = provider
    header = b64url_encode(b'{"alg":"none"}')
    body = b64url_encode(json.dumps(claims(sub="admin")).encode())
    assert rejection(f"{header}.{body}.", jwks) == "unsecured"


def test_ignores_a_key_embedded_in_the_header(provider):
    _, jwks = provider
    attacker = ml_dsa_private_key_from_seed("ML-DSA-65", secrets.token_bytes(32))
    token = sign_ml_dsa_jwt(attacker, "ML-DSA-65", "pq-1", claims(sub="admin"))
    assert rejection(token, jwks) == "bad-signature"


def test_rejects_unknown_keys_expired_tokens_and_wrong_audience(provider):
    key, jwks = provider
    assert rejection(sign_ml_dsa_jwt(key, "ML-DSA-65", "other", claims()), jwks) == "unknown-key"
    assert rejection(sign_ml_dsa_jwt(key, "ML-DSA-65", "pq-1", claims(exp=1)), jwks) == "expired"
    assert rejection(sign_ml_dsa_jwt(key, "ML-DSA-65", "pq-1", claims(aud="other")), jwks) == "claim-mismatch"
    assert rejection(sign_ml_dsa_jwt(key, "ML-DSA-65", "pq-1", claims(nonce="a")), jwks, nonce="b") == "claim-mismatch"


# --- Cross-language interop ---------------------------------------------------

FIXTURES = os.environ.get("INTEROP_FIXTURES")
needs_fixtures = pytest.mark.skipif(not FIXTURES, reason="run through `npm run interop`")


@pytest.fixture(scope="module")
def node():
    with open(FIXTURES, encoding="utf-8") as file:
        return json.load(file)


@needs_fixtures
@pytest.mark.parametrize("alg", ["ES256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"])
def test_verifies_tokens_signed_by_node(node, alg):
    result = verify_id_token(
        node["tokens"][alg], node["jwks"], issuer=node["issuer"], audience=node["audience"], algorithms=[alg]
    )
    assert result.header["alg"] == alg
    assert result.claims["email"] == "alice.nakamura@example.com"


@needs_fixtures
def test_rejects_the_same_attacks_as_the_typescript_verifier(node):
    for name, expected in node["expectedRejections"].items():
        with pytest.raises(TokenRejected) as info:
            verify_id_token(
                node["attacks"][name],
                node["jwks"],
                issuer=node["issuer"],
                audience=node["audience"],
                algorithms=["ML-DSA-65", "ES256"],
            )
        assert info.value.code == expected, name


@needs_fixtures
def test_derives_the_same_public_key_from_a_seed_as_node(node):
    seed = b64url_decode(node["seedKey"]["priv"])
    key = ml_dsa_private_key_from_seed("ML-DSA-65", seed)
    assert akp_public_jwk(key, "ML-DSA-65", "seed")["pub"] == node["seedKey"]["pub"]


@needs_fixtures
def test_signs_a_token_for_node_to_verify(node):
    key = ml_dsa_private_key_from_seed("ML-DSA-65", secrets.token_bytes(32))
    token = sign_ml_dsa_jwt(key, "ML-DSA-65", "py-1", claims(iss=node["issuer"], aud=node["audience"]))
    with open(os.environ["INTEROP_OUT"], "w", encoding="utf-8") as file:
        json.dump({"token": token, "jwk": akp_public_jwk(key, "ML-DSA-65", "py-1")}, file)
