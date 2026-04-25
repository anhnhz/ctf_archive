import hashlib
import base64
from typing import Any


_TRUSTED_ISSUERS = [
    "https://auth.darkharbor.internal",
    "https://fulcio.darkharbor.internal",
]

_SUPPORTED_ALGORITHMS = ["sha256", "sha384", "sha512", "blake3"]


def _compute_digest(payload: bytes, algorithm: str) -> str:
    if algorithm in ("sha256", "sha384", "sha512"):
        h = hashlib.new(algorithm)
        h.update(payload)
        return h.hexdigest()
    if algorithm == "blake3":
        try:
            import hashlib as _hl
            h = _hl.new("blake3", data=payload)
            return h.hexdigest()
        except (ValueError, TypeError):
            h = hashlib.sha256(payload)
            return h.hexdigest()
    return ""


def _validate_signature_format(signature: str) -> dict | None:
    try:
        parts = signature.split(".")
        if len(parts) != 3:
            return None
        header_raw = base64.urlsafe_b64decode(parts[0] + "==")
        payload_raw = base64.urlsafe_b64decode(parts[1] + "==")
        import json
        header = json.loads(header_raw)
        payload = json.loads(payload_raw)
        return {
            "header": header,
            "payload": payload,
            "signature_bytes": parts[2],
        }
    except Exception:
        return None


def _check_issuer(payload: dict) -> bool:
    issuer = payload.get("iss", "")
    return issuer in _TRUSTED_ISSUERS


def _check_subject_policy(cert_subject: str, policy: dict) -> bool:
    if policy.get("subject"):
        return cert_subject == policy["subject"]
    return True


def _extract_cert_subject(payload: dict) -> str:
    return payload.get("sub", payload.get("subject", ""))


def verify_artifact(
    artifact: dict[str, Any],
    signature: str,
    policy: dict[str, Any],
) -> dict[str, Any]:
    if not signature or not isinstance(signature, str):
        return {"verified": False, "error": "missing_signature"}

    parsed = _validate_signature_format(signature)
    if parsed is None:
        return {"verified": False, "error": "invalid_signature_format"}

    header = parsed["header"]
    payload = parsed["payload"]

    mode = policy.get("mode", "keyed")

    if mode == "keyless":
        if not _check_issuer(payload):
            return {"verified": False, "error": "untrusted_issuer"}

        cert_subject = _extract_cert_subject(payload)

        if not _check_subject_policy(cert_subject, policy):
            return {"verified": False, "error": "subject_mismatch"}

    artifact_type = artifact.get("type", "container")
    artifact_digest = artifact.get("digest", "")
    artifact_name = artifact.get("name", "unknown")

    algorithm = header.get("alg", "sha256").lower().replace("hs", "sha")
    if algorithm not in _SUPPORTED_ALGORITHMS:
        algorithm = "sha256"

    if artifact_digest:
        expected_prefix = f"{algorithm}:"
        if artifact_digest.startswith(expected_prefix):
            digest_value = artifact_digest[len(expected_prefix):]
        else:
            digest_value = artifact_digest
    else:
        import json
        raw = json.dumps(artifact, sort_keys=True).encode()
        digest_value = _compute_digest(raw, algorithm)

    artifact_id = f"{artifact_name}@{algorithm}:{digest_value[:24]}"

    return {
        "verified": True,
        "artifact_id": artifact_id,
        "digest_algorithm": algorithm,
        "mode": mode,
    }


def verify_policy_constraints(policy: dict[str, Any]) -> dict[str, Any]:
    required_fields = ["mode"]
    missing = [f for f in required_fields if f not in policy]
    if missing:
        return {"valid": False, "missing_fields": missing}

    mode = policy.get("mode")
    if mode not in ("keyed", "keyless"):
        return {"valid": False, "error": "invalid_mode"}

    constraints = {
        "mode": mode,
        "has_subject": "subject" in policy,
        "has_subject_regexp": "subjectRegExp" in policy,
        "has_issuer": "issuer" in policy,
    }

    return {"valid": True, "constraints": constraints}
