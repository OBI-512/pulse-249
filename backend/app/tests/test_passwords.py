import base64

import pytest

from app.security.passwords import (
    ALGORITHM,
    DERIVED_KEY_BYTES,
    ITERATIONS,
    SALT_BYTES,
    hash_password,
    verify_password,
)


def test_hash_password_returns_expected_format():
    password_hash = hash_password("Correct Horse Battery Staple")

    parts = password_hash.split("$")

    assert len(parts) == 4
    assert parts[0] == ALGORITHM
    assert parts[1] == str(ITERATIONS)

    salt = base64.b64decode(parts[2], validate=True)
    derived_key = base64.b64decode(parts[3], validate=True)

    assert len(salt) == SALT_BYTES
    assert len(derived_key) == DERIVED_KEY_BYTES


def test_hash_password_does_not_store_plaintext():
    password = "My-Secure-Password-123!"

    password_hash = hash_password(password)

    assert password not in password_hash


def test_hash_password_generates_unique_salts():
    password = "Same Password"

    first_hash = hash_password(password)
    second_hash = hash_password(password)

    assert first_hash != second_hash

    first_parts = first_hash.split("$")
    second_parts = second_hash.split("$")

    assert first_parts[2] != second_parts[2]


def test_verify_password_accepts_correct_password():
    password = "Correct-Password-123!"

    password_hash = hash_password(password)

    assert verify_password(password, password_hash) is True


def test_verify_password_rejects_incorrect_password():
    password_hash = hash_password("Correct-Password-123!")

    assert verify_password("Wrong-Password-123!", password_hash) is False


def test_verify_password_supports_unicode_passwords():
    password = "Pässwörd-安全-🔐"

    password_hash = hash_password(password)

    assert verify_password(password, password_hash) is True


def test_hash_password_rejects_empty_password():
    with pytest.raises(ValueError, match="must not be empty"):
        hash_password("")


def test_hash_password_rejects_non_string_password():
    with pytest.raises(TypeError, match="must be a string"):
        hash_password(None)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "malformed_hash",
    [
        "",
        "invalid",
        "bcrypt$600000$salt$key",
        "pbkdf2_sha256$not-a-number$salt$key",
        "pbkdf2_sha256$0$c2FsdA==$a2V5",
        "pbkdf2_sha256$600000$%%%$a2V5",
        "pbkdf2_sha256$600000$c2FsdA==$%%%",
        "pbkdf2_sha256$600000$$",
    ],
)
def test_verify_password_rejects_malformed_hashes(malformed_hash):
    assert verify_password("password", malformed_hash) is False


def test_verify_password_rejects_non_string_inputs():
    password_hash = hash_password("password")

    assert verify_password(None, password_hash) is False  # type: ignore[arg-type]
    assert verify_password("password", None) is False  # type: ignore[arg-type]


def test_verify_password_uses_stored_iteration_count():
    password = "Iteration-Test-Password"

    password_hash = hash_password(password)
    parts = password_hash.split("$")

    salt = base64.b64decode(parts[2], validate=True)
    derived_key = base64.b64decode(parts[3], validate=True)

    # Reconstruct a valid hash using a different positive iteration count.
    # Verification must honor the iteration count encoded in the stored hash.
    alternate_iterations = ITERATIONS + 1

    import hashlib

    alternate_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        alternate_iterations,
        dklen=len(derived_key),
    )

    alternate_hash = (
        f"{ALGORITHM}${alternate_iterations}"
        f"${parts[2]}${base64.b64encode(alternate_key).decode('ascii')}"
    )

    assert verify_password(password, alternate_hash) is True


def test_verify_password_rejects_modified_hash():
    password_hash = hash_password("password")

    parts = password_hash.split("$")
    key = bytearray(base64.b64decode(parts[3], validate=True))
    key[0] ^= 0x01

    modified_hash = (
        f"{parts[0]}${parts[1]}${parts[2]}"
        f"${base64.b64encode(bytes(key)).decode('ascii')}"
    )

    assert verify_password("password", modified_hash) is False
