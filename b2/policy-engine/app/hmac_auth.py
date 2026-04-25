import hashlib
import hmac
import time


def validate_hmac(
    method: str,
    path: str,
    body: bytes,
    header_value: str,
    hmac_secret: str,
    redis_client=None,
) -> dict:
    if not header_value:
        return {"valid": False, "error": "missing_hmac_header"}

    parts = header_value.split(":")
    if len(parts) != 3:
        return {"valid": False, "error": "invalid_hmac_format"}

    scheme, timestamp_str, provided_sig = parts

    if scheme != "SHA256":
        return {"valid": False, "error": "unsupported_hmac_scheme"}

    try:
        timestamp = int(timestamp_str)
    except (ValueError, TypeError):
        return {"valid": False, "error": "invalid_timestamp"}

    now = int(time.time())
    if abs(now - timestamp) > 30:
        return {"valid": False, "error": "timestamp_expired"}

    body_hash = hashlib.sha256(body).hexdigest()

    message = f"{method.upper()}\n{path}\n{timestamp_str}\n{body_hash}"

    expected_sig = hmac.new(
        hmac_secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected_sig, provided_sig):
        return {"valid": False, "error": "signature_mismatch"}

    if redis_client:
        nonce_key = f"hmac_nonce:{timestamp_str}:{path}"
        try:
            if redis_client.exists(nonce_key):
                return {"valid": False, "error": "nonce_replay_detected"}
            redis_client.setex(nonce_key, 60, "1")
        except Exception:
            pass

    return {"valid": True, "timestamp": timestamp}


def generate_hmac(
    method: str,
    path: str,
    body: bytes,
    hmac_secret: str,
    timestamp: int | None = None,
) -> str:
    if timestamp is None:
        timestamp = int(time.time())

    body_hash = hashlib.sha256(body).hexdigest()
    message = f"{method.upper()}\n{path}\n{timestamp}\n{body_hash}"

    sig = hmac.new(
        hmac_secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return f"SHA256:{timestamp}:{sig}"
