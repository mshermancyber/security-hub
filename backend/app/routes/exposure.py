"""Exposure routes — domain spoofing + cred-leak per org."""
from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException

from ..enrich.spoofing import scan_all, scan_org
from ..integrations import hibp

router = APIRouter(prefix="/api/exposure", tags=["exposure"])

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$")
_ORG_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,40}$")


@router.get("/spoofing")
def spoofing_all():
    return scan_all()


@router.get("/spoofing/{org_id}")
def spoofing_one(org_id: str):
    if not _ORG_RE.match(org_id):
        raise HTTPException(400, "invalid org id")
    return scan_org(org_id)


@router.get("/breaches/{domain}")
async def domain_breaches(domain: str):
    if not _DOMAIN_RE.match(domain):
        raise HTTPException(400, "invalid domain")
    return await hibp.breaches_for_domain(domain)


@router.get("/account/{email}")
async def account_breach(email: str):
    if not _EMAIL_RE.match(email):
        raise HTTPException(400, "invalid email")
    return await hibp.breached_account(email)
