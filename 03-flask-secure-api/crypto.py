#!/usr/bin/env python3
"""
Cryptographic Password Hashing and Verification Service
Utilizes Bcrypt with per-password random salt generation and adaptive work factor.
Defends against offline dictionary attacks, rainbow tables, and timing side-channels.
"""

import os
import bcrypt


def hash_password(plain_text: str, rounds: int = 12) -> str:
    """
    Hashes a plaintext password using Bcrypt with a newly generated random salt.
    Enforces password byte-length boundaries to avoid Bcrypt 72-byte truncation issues.
    """
    if not isinstance(plain_text, str) or not plain_text:
        raise ValueError("Password must be a non-empty string.")

    password_bytes = plain_text.encode("utf-8")
    if len(password_bytes) > 72:
        raise ValueError("Password length exceeds Bcrypt maximum bound of 72 bytes.")

    salt = bcrypt.gensalt(rounds=rounds)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")


def verify_password(plain_text: str, stored_hash: str) -> bool:
    """
    Verifies a plaintext password against a stored Bcrypt hash in constant time.
    Safely handles malformed hashes without crashing or leaking state.
    """
    if not isinstance(plain_text, str) or not isinstance(stored_hash, str):
        return False
    if not plain_text or not stored_hash:
        return False

    try:
        return bcrypt.checkpw(
            plain_text.encode("utf-8"),
            stored_hash.encode("utf-8")
        )
    except (ValueError, TypeError):
        # Malformed hash or invalid salt structure
        return False


if __name__ == "__main__":
    # Ephemeral demonstration input for testing unique salt generation
    demo_pass = os.getenv("DEMO_PASS", "EphemeralDemo123!Secure")  # nosec: B105
    hash1 = hash_password(demo_pass)
    hash2 = hash_password(demo_pass)

    print(f"Run 1: {hash1}")
    print(f"Run 2: {hash2}")
    print(f"Verification 1: {verify_password(demo_pass, hash1)}")
    print(f"Verification 2: {verify_password(demo_pass, hash2)}")
