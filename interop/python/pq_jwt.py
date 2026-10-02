"""Verify OpenID Connect ID tokens signed with ES256 or ML-DSA (RFC 9964).

A small, dependency-light verifier built on pyca/cryptography (>= 48, which
added ML-DSA). It applies the same checks, in the same order and with the same
rejection codes, as the TypeScript verifier in packages/token-kit:

 1. refuse unsigned tokens ("alg": "none");
 2. refuse algorithms outside the caller's allowlist;
 3. take the key from the provider's JWKS only, matched by kid AND alg
    (keys embedded in the token header are ignored);
 4. check the signature, then iss, aud, nonce and exp.

RFC 9964 in one paragraph: ML-DSA keys are JWKs with "kty": "AKP", the
algorithm in "alg", the raw public key in "pub" (base64url) and, for private
keys, the 32-byte seed in "priv". Signatures are "pure" ML-DSA over the usual
JWS signing input, with an empty context string.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, mldsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

ML_DSA_PUBLIC_KEYS = {
    "ML-DSA-44": mldsa.MLDSA44PublicKey,
    "ML-DSA-65": mldsa.MLDSA65PublicKey,
    "ML-DSA-87": mldsa.MLDSA87PublicKey,
}
ML_DSA_PRIVATE_KEYS = {
    "ML-DSA-44": mldsa.MLDSA44PrivateKey,
    "ML-DSA-65": mldsa.MLDSA65PrivateKey,
    "ML-DSA-87": mldsa.MLDSA87PrivateKey,
}


class TokenRejected(Exception):
    """Raised when a token must not be trusted. `code` is stable and machine-readable."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass
class VerifiedToken:
    header: dict[str, Any]
    claims: dict[str, Any]


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def verify_id_token(
    token: str,
    jwks: dict[str, Any],
    *,
    issuer: str,
    audience: str,
    algorithms: list[str],
    nonce: str | None = None,
    now: float | None = None,
) -> VerifiedToken:
    """Return the verified header and claims, or raise TokenRejected."""
    try:
        encoded_header, encoded_claims, encoded_signature = token.split(".")
        header = json.loads(b64url_decode(encoded_header))
        claims = json.loads(b64url_decode(encoded_claims))
        signature = b64url_decode(encoded_signature)
    except (ValueError, TypeError) as error:
        raise TokenRejected("malformed", "The token is not a well-formed JWT.") from error

    alg = header.get("alg")
    if not isinstance(alg, str) or alg.lower() == "none":
        raise TokenRejected("unsecured", 'The token is not signed (alg "none").')
    if alg not in algorithms:
        allowed = ", ".join(algorithms)
        raise TokenRejected("alg-not-allowed", f"The token is signed with {alg}, but only {allowed} is accepted.")

    # The key always comes from the trusted JWKS, never from the token itself.
    key = next((k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid") and k.get("alg") == alg), None)
    if key is None:
        raise TokenRejected("unknown-key", "None of the trusted public keys matches this token.")

    signing_input = f"{encoded_header}.{encoded_claims}".encode("ascii")
    if not _signature_is_valid(alg, key, signing_input, signature):
        raise TokenRejected("bad-signature", "The signature does not match: the token was altered or forged.")

    if not all(name in claims for name in ("sub", "iat", "exp")):
        raise TokenRejected("claim-mismatch", "The token is missing a required claim (sub, iat or exp).")
    if claims.get("iss") != issuer:
        raise TokenRejected("claim-mismatch", "Unexpected issuer.")
    audiences = claims["aud"] if isinstance(claims.get("aud"), list) else [claims.get("aud")]
    if audience not in audiences:
        raise TokenRejected("claim-mismatch", "The token was issued to a different app.")
    if nonce is not None and claims.get("nonce") != nonce:
        raise TokenRejected("claim-mismatch", "The token was issued for a different login attempt.")
    if claims["exp"] <= (time.time() if now is None else now):
        raise TokenRejected("expired", "The token has expired.")

    return VerifiedToken(header=header, claims=claims)


def _signature_is_valid(alg: str, jwk: dict[str, Any], signing_input: bytes, signature: bytes) -> bool:
    try:
        if alg in ML_DSA_PUBLIC_KEYS:
            if jwk.get("kty") != "AKP":
                return False
            public_key = ML_DSA_PUBLIC_KEYS[alg].from_public_bytes(b64url_decode(jwk["pub"]))
            public_key.verify(signature, signing_input)  # pure ML-DSA, empty context
            return True
        if alg == "ES256":
            if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or len(signature) != 64:
                return False
            numbers = ec.EllipticCurvePublicNumbers(
                int.from_bytes(b64url_decode(jwk["x"]), "big"),
                int.from_bytes(b64url_decode(jwk["y"]), "big"),
                ec.SECP256R1(),
            )
            # JWS carries r || s; cryptography wants DER.
            der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
            numbers.public_key().verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
            return True
    except (InvalidSignature, ValueError, KeyError):
        return False
    return False


# --- Signing helpers (used by the tests and the interop check) ----------------


def ml_dsa_private_key_from_seed(alg: str, seed: bytes):
    """RFC 9964 private keys are the 32-byte seed ("priv")."""
    return ML_DSA_PRIVATE_KEYS[alg].from_seed_bytes(seed)


def akp_public_jwk(private_key, alg: str, kid: str) -> dict[str, str]:
    return {"kty": "AKP", "alg": alg, "kid": kid, "pub": b64url_encode(private_key.public_key().public_bytes_raw())}


def sign_ml_dsa_jwt(private_key, alg: str, kid: str, claims: dict[str, Any]) -> str:
    header = {"alg": alg, "kid": kid, "typ": "JWT"}
    signing_input = ".".join(
        b64url_encode(json.dumps(part, separators=(",", ":")).encode("utf-8")) for part in (header, claims)
    )
    return f"{signing_input}.{b64url_encode(private_key.sign(signing_input.encode('ascii')))}"
