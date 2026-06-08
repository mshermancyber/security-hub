"""CRUD endpoints for orgs.json — lets users add/edit/remove watched orgs."""
from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..config import TAXONOMY_DIR

router = APIRouter(prefix="/api/orgs-admin", tags=["orgs-admin"])

ORGS_PATH = TAXONOMY_DIR / "orgs.json"

ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,40}$")

# Serializes read-modify-write of orgs.json across concurrent worker threads.
# FastAPI runs sync routes in a threadpool, so without this two simultaneous
# PUTs can race and silently drop one another's changes (TOCTOU on _load → mutate → _save).
_WRITE_LOCK = threading.Lock()


class OrgPayload(BaseModel):
    id: str = Field(min_length=2, max_length=40)
    name: str = Field(min_length=1, max_length=80)
    sector: str | None = Field(default=None, max_length=80)
    country: str | None = Field(default=None, max_length=80)
    ticker: str | None = Field(default=None, max_length=20)
    # Cap array sizes so an attacker (or careless operator) can't push a
    # 10 000-element keyword list that later blows past SQLITE_LIMIT_EXPR_DEPTH
    # in routes/orgs.py:_keyword_news.
    brands: list[str] = Field(default_factory=list, max_length=64)
    subsidiaries: list[str] = Field(default_factory=list, max_length=64)
    domains: list[str] = Field(default_factory=list, max_length=64)
    aliases: list[str] = Field(default_factory=list, max_length=64)
    tech_stack: list[str] = Field(default_factory=list, max_length=64)
    watch_keywords: list[str] = Field(default_factory=list, max_length=64)


def _load() -> dict:
    return json.loads(ORGS_PATH.read_text())


def _save(doc: dict) -> None:
    """Atomic write — tempfile + fsync + os.replace.

    Direct `write_text` truncates orgs.json to zero bytes on crash mid-write,
    nuking every watched org. Write to a sibling tempfile and rename it in.
    """
    payload = json.dumps(doc, indent=2) + "\n"
    fd, tmp_path = tempfile.mkstemp(
        dir=str(ORGS_PATH.parent), prefix=".orgs.", suffix=".json.tmp"
    )
    tmp = Path(tmp_path)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, ORGS_PATH)
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _cap_string_lengths(payload: OrgPayload) -> None:
    """Cap each per-element string at 80 chars. Bigger entries are operator
    error and would only bloat downstream LIKE patterns."""
    for attr in ("brands", "subsidiaries", "domains", "aliases", "tech_stack", "watch_keywords"):
        arr = getattr(payload, attr) or []
        if any(not isinstance(v, str) or len(v) > 80 for v in arr):
            raise HTTPException(400, f"{attr} entries must be strings ≤ 80 chars")


@router.get("")
def list_orgs():
    with _WRITE_LOCK:
        return _load()


@router.post("")
def create_org(payload: OrgPayload):
    if not ID_RE.match(payload.id):
        raise HTTPException(400, "id must match ^[a-z0-9][a-z0-9_-]{1,40}$")
    _cap_string_lengths(payload)
    with _WRITE_LOCK:
        doc = _load()
        if any(o["id"] == payload.id for o in doc.get("orgs", [])):
            raise HTTPException(409, f"org {payload.id} already exists")
        doc.setdefault("orgs", []).append(payload.model_dump())
        _save(doc)
    return {"ok": True, "org": payload.model_dump()}


@router.put("/{org_id}")
def update_org(org_id: str, payload: OrgPayload):
    if not ID_RE.match(org_id):
        raise HTTPException(400, "invalid org id")
    if payload.id != org_id:
        raise HTTPException(400, "payload id mismatch")
    _cap_string_lengths(payload)
    with _WRITE_LOCK:
        doc = _load()
        orgs = doc.get("orgs", [])
        for i, o in enumerate(orgs):
            if o["id"] == org_id:
                orgs[i] = payload.model_dump()
                _save(doc)
                return {"ok": True, "org": orgs[i]}
    raise HTTPException(404, f"unknown org {org_id}")


@router.delete("/{org_id}")
def delete_org(org_id: str):
    if not ID_RE.match(org_id):
        raise HTTPException(400, "invalid org id")
    with _WRITE_LOCK:
        doc = _load()
        before = len(doc.get("orgs", []))
        doc["orgs"] = [o for o in doc.get("orgs", []) if o["id"] != org_id]
        if len(doc["orgs"]) == before:
            raise HTTPException(404, f"unknown org {org_id}")
        _save(doc)
    return {"ok": True}
