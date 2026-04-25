import hashlib
import hmac as hmac_mod
import json
import os
import uuid
import time
import base64
from contextlib import asynccontextmanager

import psycopg2
import psycopg2.extras
import redis as redis_lib
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Any

from .crypto_utils import derive_key, encrypt_flag
from .hmac_auth import validate_hmac
from .verify import verify_artifact, verify_policy_constraints
from .routes_phase1 import router as phase1_router


DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://darkharbor:harb0r_s3cret_2026@postgres:5432/darkharbor",
)
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379")
FLAG = os.environ.get("FLAG", "FLAG{fake_flag}")
HMAC_SECRET = os.environ.get("HMAC_SECRET", "a]Kx9#mP$vQ2nR7wF4jL8cB5hT0yU3eA")
SIGNING_KEY_SEED = os.environ.get("SIGNING_KEY_SEED", "dh_sign_seed_7f3a9c2e")

_redis: redis_lib.Redis | None = None


def _get_db():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    return conn


def _get_redis() -> redis_lib.Redis:
    global _redis
    if _redis is None:
        _redis = redis_lib.from_url(REDIS_URL, decode_responses=True)
    return _redis


def _get_workspace_seal(workspace_id: int) -> str:
    r = _get_redis()
    key = f"darkharbor:session_seal:{workspace_id}"
    seal = r.get(key)
    if not seal:
        seal = uuid.uuid4().hex
        r.set(key, seal)
    return seal


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        _get_redis().ping()
    except Exception:
        pass
    yield


app = FastAPI(
    title="Harbor Policy Engine",
    version="2.4.1",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)

app.include_router(phase1_router)


class ArtifactPayload(BaseModel):
    name: str
    type: str = "container"
    digest: str = ""
    registry: str = ""
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicyPayload(BaseModel):
    mode: str = "keyed"
    subject: str | None = None
    subjectRegExp: str | None = None
    issuer: str | None = None
    requiredAnnotations: dict[str, str] = Field(default_factory=dict)


class VerifyRequest(BaseModel):
    artifact: ArtifactPayload
    signature: str
    policy: PolicyPayload


class SecretExportRequest(BaseModel):
    artifact_id: str
    verification_token: str
    export_format: str = "encrypted"


@app.get("/health/policy-engine")
@app.get("/health")
async def health():
    checks = {"database": "unknown", "redis": "unknown"}
    try:
        conn = _get_db()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.close()
        conn.close()
        checks["database"] = "healthy"
    except Exception:
        checks["database"] = "degraded"

    try:
        _get_redis().ping()
        checks["redis"] = "healthy"
    except Exception:
        checks["redis"] = "degraded"

    status = "ok" if all(v == "healthy" for v in checks.values()) else "degraded"
    return {"status": status, "checks": checks, "version": "2.4.1"}


@app.post("/api/artifacts/verify")
async def api_verify_artifact(req: VerifyRequest):
    policy_check = verify_policy_constraints(req.policy.model_dump(exclude_none=True))
    if not policy_check.get("valid"):
        raise HTTPException(status_code=422, detail=policy_check)

    artifact_dict = req.artifact.model_dump()
    policy_dict = req.policy.model_dump(exclude_none=True)

    result = verify_artifact(artifact_dict, req.signature, policy_dict)

    if not result.get("verified"):
        return JSONResponse(
            status_code=403,
            content={
                "verified": False,
                "error": result.get("error", "verification_failed"),
            },
        )

    r = _get_redis()
    vtok = str(uuid.uuid4())
    token_data = json.dumps({
        "artifact_id": result["artifact_id"],
        "digest_algorithm": result.get("digest_algorithm", "sha256"),
        "mode": result.get("mode", "keyed"),
        "verified_at": int(time.time()),
    })
    r.setex(f"vtok:{vtok}", 300, token_data)

    return {
        "verified": True,
        "artifact_id": result["artifact_id"],
        "verification_token": vtok,
        "digest_algorithm": result.get("digest_algorithm"),
        "expires_in": 300,
    }


@app.post("/api/secrets/export")
async def api_export_secret(req: SecretExportRequest):
    r = _get_redis()
    token_key = f"vtok:{req.verification_token}"
    token_raw = r.get(token_key)

    if not token_raw:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_or_expired_verification_token"},
        )

    try:
        token_data = json.loads(token_raw)
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(status_code=401, detail={"error": "corrupted_token_data"})

    if token_data.get("artifact_id") != req.artifact_id:
        raise HTTPException(
            status_code=403,
            detail={"error": "artifact_id_mismatch"},
        )

    r.delete(token_key)

    if req.export_format == "encrypted":
        return {
            "status": "exported",
            "artifact_id": req.artifact_id,
            "encrypted_secret": "use_override_endpoint_to_obtain",
            "encryption": "AES-256-GCM",
            "key_derivation": "HMAC-SHA256(signing_key, session_seal)",
        }

    if req.export_format == "metadata":
        return {
            "status": "exported",
            "artifact_id": req.artifact_id,
            "key_derivation": "HMAC-SHA256(signing_key, session_seal)",
            "encryption": "AES-256-GCM",
            "nonce_length": 12,
        }

    raise HTTPException(status_code=400, detail={"error": "unsupported_export_format"})


def _validate_jwt_bearer(auth_header: str | None) -> dict | None:
    if not auth_header or not auth_header.startswith("Bearer "):
        return None

    token = auth_header[7:]
    parts = token.split(".")
    if len(parts) != 3:
        return None

    try:
        signing_input = f"{parts[0]}.{parts[1]}"
        expected_sig = hmac_mod.new(
            HMAC_SECRET.encode("utf-8"),
            signing_input.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        provided_sig = base64.urlsafe_b64decode(parts[2] + "=" * (4 - len(parts[2]) % 4))
        if not hmac_mod.compare_digest(expected_sig, provided_sig):
            return None
    except Exception:
        return None

    try:
        padding = "=" * (4 - len(parts[1]) % 4)
        payload_raw = base64.urlsafe_b64decode(parts[1] + padding)
        payload = json.loads(payload_raw)
    except Exception:
        return None

    if payload.get("role") != "pipeline_admin":
        return None

    exp = payload.get("exp")
    if exp and isinstance(exp, (int, float)):
        if time.time() > exp:
            return None

    return payload


def _validate_pipeline_state(workspace_id: int, required_state: str) -> bool:
    try:
        conn = _get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            "SELECT pipeline_state FROM workspaces WHERE id = %s",
            (workspace_id,),
        )
        row = cur.fetchone()
        cur.close()
        conn.close()
        if not row:
            return False
        return row["pipeline_state"].upper() == required_state.upper()
    except Exception:
        return False


class OverrideRequest(BaseModel):
    workspace_id: int
    reason: str
    scope: str = "deploy"
    target_state: str = "APPROVED"


@app.post("/internal/admin/policy-override")
async def internal_policy_override(request: Request):
    auth_header = request.headers.get("authorization")
    jwt_payload = _validate_jwt_bearer(auth_header)
    if jwt_payload is None:
        return JSONResponse(status_code=401, content={"error": "unauthorized", "detail": "invalid_jwt_credentials"})

    body = await request.body()
    hmac_header = request.headers.get("x-internal-hmac", "")
    hmac_result = validate_hmac(method=request.method, path=str(request.url.path), body=body, header_value=hmac_header, hmac_secret=HMAC_SECRET, redis_client=_get_redis())
    if not hmac_result.get("valid"):
        return JSONResponse(status_code=403, content={"error": "hmac_verification_failed", "detail": hmac_result.get("error", "unknown")})

    pipeline_state_header = request.headers.get("x-pipeline-state", "")
    try:
        body_json = json.loads(body)
        req = OverrideRequest(**body_json)
    except Exception:
        raise HTTPException(status_code=400, detail={"error": "invalid_request_body"})

    if not pipeline_state_header:
        return JSONResponse(status_code=400, content={"error": "missing_pipeline_state_header"})
    if not _validate_pipeline_state(req.workspace_id, "REVIEW"):
        return JSONResponse(status_code=409, content={"error": "pipeline_state_conflict", "detail": "workspace must be in REVIEW state"})

    r = _get_redis()
    deploy_token = str(uuid.uuid4())
    workspace_seal = _get_workspace_seal(req.workspace_id)
    token_entry = json.dumps({"workspace_id": req.workspace_id, "scope": req.scope, "target_state": req.target_state, "issued_by": jwt_payload.get("sub", "unknown"), "issued_at": int(time.time())})
    r.setex(f"deploy:{req.workspace_id}:{deploy_token}", 30, token_entry)

    nonce_bytes = hashlib.sha256(f"{deploy_token}:{workspace_seal}".encode()).digest()[:12]
    from .crypto_utils import encrypt_flag_deterministic
    token_signing_key = hmac_mod.new(SIGNING_KEY_SEED.encode("utf-8"), deploy_token.encode("utf-8"), hashlib.sha256).hexdigest()
    enc_secret = encrypt_flag_deterministic(FLAG, token_signing_key, workspace_seal, nonce_bytes)

    try:
        conn = _get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO deploy_tokens (workspace_id, token) VALUES (%s, %s)", (req.workspace_id, deploy_token))
        conn.commit()
        cur.close()
        conn.close()
    except Exception:
        pass

    result = {"status": "override_accepted", "deploy_token": deploy_token, "encrypted_secret": enc_secret, "token_ttl_ms": 1000, "nonce": base64.b64encode(nonce_bytes).decode("utf-8"), "encryption": "AES-256-GCM"}
    r.setex(f"override_result:{req.workspace_id}", 30, json.dumps(result))
    return result


@app.get("/internal/status")
async def internal_status():
    r = _get_redis()
    try:
        active_tokens = len(r.keys("deploy:*"))
        active_vtoks = len(r.keys("vtok:*"))
    except Exception:
        active_tokens = -1
        active_vtoks = -1

    try:
        conn = _get_db()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM workspaces")
        ws_count = cur.fetchone()[0]
        cur.execute(
            "SELECT pipeline_state, COUNT(*) FROM workspaces GROUP BY pipeline_state"
        )
        state_counts = {row[0]: row[1] for row in cur.fetchall()}
        cur.close()
        conn.close()
    except Exception:
        ws_count = -1
        state_counts = {}

    return {
        "engine": "policy-engine",
        "version": "2.4.1",
        "workspaces": ws_count,
        "pipeline_states": state_counts,
        "active_deploy_tokens": active_tokens,
        "active_verification_tokens": active_vtoks,
    }


@app.post("/api/policies/validate")
async def api_validate_policy(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail={"error": "invalid_json"})

    result = verify_policy_constraints(body)
    if not result.get("valid"):
        return JSONResponse(status_code=422, content=result)

    return {"valid": True, "constraints": result.get("constraints", {})}


@app.get("/api/policies/schema")
async def api_policy_schema():
    return {
        "type": "object",
        "required": ["mode"],
        "properties": {
            "mode": {
                "type": "string",
                "enum": ["keyed", "keyless"],
            },
            "subject": {
                "type": "string",
                "description": "Exact subject identity match",
            },
            "subjectRegExp": {
                "type": "string",
                "description": "Regular expression for subject matching",
            },
            "issuer": {
                "type": "string",
                "description": "Expected certificate issuer",
            },
            "requiredAnnotations": {
                "type": "object",
                "additionalProperties": {"type": "string"},
            },
        },
    }


@app.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=404,
        content={"error": "not_found", "path": str(request.url.path)},
    )


@app.exception_handler(500)
async def server_error_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"error": "internal_server_error"},
    )
