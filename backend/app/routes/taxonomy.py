"""Taxonomy read API — lets the frontend list known entities for command palette."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..db import load_taxonomy

router = APIRouter(prefix="/api/taxonomy", tags=["taxonomy"])

_VALID = {"vendors", "ai_companies", "threat_actors", "threat_actors_mitre",
          "sectors", "sources", "orgs", "routing"}


@router.get("/{name}")
def get_taxonomy(name: str):
    if name not in _VALID:
        raise HTTPException(404, f"Unknown taxonomy {name}")
    try:
        return load_taxonomy(name)
    except FileNotFoundError:
        raise HTTPException(404, "Taxonomy file missing")
