from __future__ import annotations

import base64
import hashlib
import hmac
import secrets


ALGORITHM = "pbkdf2_sha256"
ITERATIONS = 600_000
SALT_BYTES = 32
DERIVED_KEY_BYTES = 32


def hash_password(password: str) -> str:
    """
    Hash a plaintext password using PBKDF2-HMAC-SHA256.

    The returned value contains the algorithm, iteration count, random salt,
    and derived key required for later verification.

    Plaintext passwords are never returned or persisted by this module.
    """
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    if not password:
        raise ValueError("Password must not be empty.")

    salt = secrets.token_bytes(SALT_BYTES)

    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        ITERATIONS,
        dklen=DERIVED_KEY_BYTES,
    )

    salt_encoded = base64.b64encode(salt).decode("ascii")
    key_encoded = base64.b64encode(derived_key).decode("ascii")

    return (
        f"{ALGORITHM}"
        f"${ITERATIONS}"
        f"${salt_encoded}"
        f"${key_encoded}"
    )


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify a plaintext password against a stored password hash.

    Invalid or malformed stored hashes return False rather than raising an
    authentication error.
    """
    if not isinstance(password, str):
        return False

    if not isinstance(password_hash, str):
        return False

    try:
        algorithm, iterations_text, salt_encoded, key_encoded = (
            password_hash.split("$", 3)
        )

        if algorithm != ALGORITHM:
            return False

        iterations = int(iterations_text)

        if iterations <= 0:
            return False

        salt = base64.b64decode(
            salt_encoded.encode("ascii"),
            validate=True,
        )

        expected_key = base64.b64decode(
            key_encoded.encode("ascii"),
            validate=True,
        )

        if not salt or not expected_key:
            return False

        actual_key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
            dklen=len(expected_key),
        )

        return hmac.compare_digest(actual_key, expected_key)

    except (ValueError, TypeError):
        return False
