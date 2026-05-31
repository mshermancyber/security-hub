"""AI enrichment routes."""
from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException, Query

from ..enrich import ai as ai_enrich
from ..integrations import llm

router = APIRouter(prefix="/api/ai", tags=["ai"])

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,8}$")
_ORG_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,40}$")


@router.get("/config")
def config():
    return llm.config_snapshot()


@router.get("/narrative/{cve_id}")
async def narrative(cve_id: str, force: bool = False):
    cve_id = (cve_id or "").upper()
    if not _CVE_RE.match(cve_id):
        raise HTTPException(400, "invalid CVE id")
    return await ai_enrich.summarize_narrative(cve_id, force=force)


@router.get("/brief")
async def brief(hours: int = Query(24, ge=1, le=168), org: str | None = Query(None, max_length=40),
                force: bool = False):
    if org is not None and not _ORG_RE.match(org):
        raise HTTPException(400, "invalid org id")
    return await ai_enrich.executive_brief(hours=hours, org=org, force=force)
