import hashlib
import hmac
import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive_key(signing_key: str, session_seal: str) -> bytes:
    raw = hmac.new(
        signing_key.encode("utf-8"),
        session_seal.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return raw[:32]


def encrypt_flag(flag: str, signing_key: str, session_seal: str) -> str:
    key = derive_key(signing_key, session_seal)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, flag.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("utf-8")


def encrypt_flag_deterministic(
    flag: str, signing_key: str, session_seal: str, nonce: bytes
) -> str:
    key = derive_key(signing_key, session_seal)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, flag.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("utf-8")
