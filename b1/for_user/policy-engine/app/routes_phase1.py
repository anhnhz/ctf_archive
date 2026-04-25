import json
import os
from typing import Any

import psycopg2
import psycopg2.extras
import redis as redis_lib
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel


DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://darkharbor:harb0r_s3cret_2026@postgres:5432/darkharbor",
)
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379")
import base64 as _base64


def _load_admin_public_key() -> str:
    b64 = os.environ.get("PHASE1_ADMIN_PUBLIC_KEY_B64", "")
    if not b64:
        return os.environ.get("PHASE1_ADMIN_PUBLIC_KEY", "")
    try:
        return _base64.b64decode(b64).decode("utf-8")
    except Exception:
        return ""


PHASE1_ADMIN_PUBLIC_KEY = _load_admin_public_key()
PHASE1_ADMIN_KID = os.environ.get("PHASE1_ADMIN_KID", "harbor-admin-kid")
PHASE1_BANNER = "\n"


_redis: redis_lib.Redis | None = None


def _get_redis() -> redis_lib.Redis:
    global _redis
    if _redis is None:
        _redis = redis_lib.from_url(REDIS_URL, decode_responses=True)
    return _redis


def _get_db():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    return conn


def _ensure_admin_seeded() -> None:
    if not PHASE1_ADMIN_PUBLIC_KEY:
        return
    try:
        conn = _get_db()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO phase1_seed_policies (kid, pem, role) VALUES (%s, %s, %s) "
            "ON CONFLICT (kid) DO UPDATE SET pem = EXCLUDED.pem, role = EXCLUDED.role",
            (PHASE1_ADMIN_KID, PHASE1_ADMIN_PUBLIC_KEY, "admin"),
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception:
        pass


class SeedRequest(BaseModel):
    workspace_id: int
    report_id: str
    kid: str


RESERVED_KIDS = {"harbor-admin-kid"}


router = APIRouter()


@router.post("/internal/policy-seed")
async def policy_seed(req: SeedRequest):
    """Phase 1 policy key seed.

    The caller identifies a build report they have already uploaded.  The
    policy engine pulls the *first* test case's `output` verbatim from redis
    and stores it as the verifier PEM for the requested `kid`, prefixed with
    a single audit banner newline.  Role is always registered as "user" for
    seeded keys; the admin key is planted separately at startup.
    """
    if req.kid in RESERVED_KIDS or req.kid.startswith("harbor-"):
        raise HTTPException(status_code=403, detail={"error": "reserved_kid"})
    r = _get_redis()
    raw = r.get(f"report:{req.workspace_id}:{req.report_id}")
    if not raw:
        raise HTTPException(status_code=404, detail={"error": "report_not_found"})
    try:
        report = json.loads(raw)
    except Exception:
        raise HTTPException(status_code=400, detail={"error": "corrupted_report"})

    cases = ((report.get("raw_results") or {}).get("cases")) or []
    if not cases or "output" not in cases[0]:
        raise HTTPException(status_code=400, detail={"error": "report_missing_output"})
    body = str(cases[0]["output"])
    pem = PHASE1_BANNER + body

    try:
        conn = _get_db()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO phase1_seed_policies (kid, pem, role) VALUES (%s, %s, %s) "
            "ON CONFLICT (kid) DO NOTHING",
            (req.kid, pem, "user"),
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": "seed_failed", "detail": str(e)})

    return {"status": "seeded", "kid": req.kid, "role": "user"}


@router.get("/internal/.well-known/jwks.json")
async def jwks_json():
    _ensure_admin_seeded()
    keys: list[dict[str, Any]] = []
    try:
        conn = _get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            "SELECT kid, pem, role FROM phase1_seed_policies ORDER BY created_at"
        )
        for row in cur.fetchall():
            keys.append(
                {
                    "kid": row["kid"],
                    "alg": "RS256",
                    "role": row["role"],
                    "pem": row["pem"],
                }
            )
        cur.close()
        conn.close()
    except Exception:
        pass
    return JSONResponse(content={"keys": keys})
