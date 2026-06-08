"""Analyst workspace — saved searches, starred items, annotations."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from ..db import fetchall, fetchone, tx

# Closed-set vocabularies for the `kind` discriminator on stars, annotations,
# and watchlists. Keeps the namespace clean and stops a misbehaving client
# from poisoning kind-filtered queries downstream.
StarKind = Literal["cve", "news", "actor", "org", "malware", "vendor", "ai_company", "sector"]
AnnotationKind = Literal["cve", "news", "actor", "org", "malware", "vendor", "ai_company", "sector"]
SavedKind = Literal["news", "vulns", "industry", "orgs", "actors", "patches"]
WatchKind = Literal["text", "entity", "cve"]

router = APIRouter(prefix="/api/workspace", tags=["workspace"])

# ----- Saved searches -----


class SavedSearchIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    kind: SavedKind
    params: dict

    def model_post_init(self, _ctx) -> None:
        # Cap serialized params at 16 KiB. The frontend stores filter state
        # here (sort keys, tag arrays); without a cap a single POST can drop
        # an arbitrary blob into the DB.
        if len(json.dumps(self.params)) > 16_384:
            raise ValueError("params payload too large (max 16 KiB)")


@router.get("/saved")
def list_saved(kind: str | None = Query(None, max_length=40)):
    if kind:
        rows = fetchall(
            "SELECT id, name, kind, params_json, created_at, last_used "
            "FROM saved_searches WHERE kind = ? ORDER BY id DESC", (kind,))
    else:
        rows = fetchall(
            "SELECT id, name, kind, params_json, created_at, last_used "
            "FROM saved_searches ORDER BY id DESC")
    out = []
    for r in rows:
        out.append({
            "id": r["id"], "name": r["name"], "kind": r["kind"],
            "params": json.loads(r["params_json"]),
            "created_at": r["created_at"], "last_used": r["last_used"],
        })
    return {"items": out}


@router.post("/saved")
def create_saved(payload: SavedSearchIn):
    now = datetime.now(timezone.utc).isoformat()
    with tx() as conn:
        cur = conn.execute(
            "INSERT INTO saved_searches (name, kind, params_json, created_at) "
            "VALUES (?, ?, ?, ?)",
            (payload.name, payload.kind, json.dumps(payload.params), now),
        )
        new_id = cur.lastrowid
    return {"id": new_id, "ok": True}


@router.delete("/saved/{search_id}")
def delete_saved(search_id: int):
    with tx() as conn:
        cur = conn.execute("DELETE FROM saved_searches WHERE id = ?", (search_id,))
        if cur.rowcount == 0:
            raise HTTPException(404, "not found")
    return {"ok": True}


@router.post("/saved/{search_id}/use")
def touch_saved(search_id: int):
    now = datetime.now(timezone.utc).isoformat()
    with tx() as conn:
        conn.execute("UPDATE saved_searches SET last_used = ? WHERE id = ?", (now, search_id))
    return {"ok": True, "last_used": now}


# ----- Starred items -----


class StarIn(BaseModel):
    kind: StarKind
    subject_id: str = Field(min_length=1, max_length=120)
    note: str | None = Field(default=None, max_length=2000)


@router.get("/stars")
def list_stars(kind: str | None = Query(None, max_length=40)):
    if kind:
        rows = fetchall(
            "SELECT id, kind, subject_id, note, starred_at FROM starred_items "
            "WHERE kind = ? ORDER BY starred_at DESC", (kind,))
    else:
        rows = fetchall(
            "SELECT id, kind, subject_id, note, starred_at FROM starred_items "
            "ORDER BY starred_at DESC")
    return {"items": [dict(r) for r in rows]}


@router.post("/stars")
def star(payload: StarIn):
    now = datetime.now(timezone.utc).isoformat()
    with tx() as conn:
        conn.execute(
            "INSERT INTO starred_items (kind, subject_id, note, starred_at) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(kind, subject_id) DO UPDATE SET note = excluded.note",
            (payload.kind, payload.subject_id, payload.note, now),
        )
    return {"ok": True}


@router.delete("/stars/{kind}/{subject_id}")
def unstar(kind: str, subject_id: str):
    with tx() as conn:
        cur = conn.execute(
            "DELETE FROM starred_items WHERE kind = ? AND subject_id = ?",
            (kind, subject_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(404, "not starred")
    return {"ok": True}


@router.get("/stars/lookup/{kind}/{subject_id}")
def star_lookup(kind: str, subject_id: str):
    r = fetchone(
        "SELECT id, note, starred_at FROM starred_items WHERE kind = ? AND subject_id = ?",
        (kind, subject_id),
    )
    if r is None:
        return {"starred": False}
    return {"starred": True, **dict(r)}


# ----- Annotations -----


class AnnotationIn(BaseModel):
    kind: AnnotationKind
    subject_id: str = Field(min_length=1, max_length=120)
    body: str = Field(min_length=1, max_length=8000)
    tags: list[str] = Field(default_factory=list, max_length=32)


class AnnotationUpdate(BaseModel):
    body: str = Field(min_length=1, max_length=8000)
    tags: list[str] = Field(default_factory=list, max_length=32)


@router.get("/annotations")
def list_annotations(kind: str | None = Query(None, max_length=40),
                     subject_id: str | None = Query(None, max_length=120)):
    where = []
    params: list = []
    if kind:
        where.append("kind = ?"); params.append(kind)
    if subject_id:
        where.append("subject_id = ?"); params.append(subject_id)
    sql = "SELECT id, kind, subject_id, body, tags_json, created_at, updated_at FROM annotations"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY updated_at DESC LIMIT 200"
    rows = fetchall(sql, tuple(params))
    return {"items": [{
        "id": r["id"], "kind": r["kind"], "subject_id": r["subject_id"],
        "body": r["body"], "tags": json.loads(r["tags_json"] or "[]"),
        "created_at": r["created_at"], "updated_at": r["updated_at"],
    } for r in rows]}


@router.post("/annotations")
def create_annotation(payload: AnnotationIn):
    now = datetime.now(timezone.utc).isoformat()
    with tx() as conn:
        cur = conn.execute(
            "INSERT INTO annotations (kind, subject_id, body, tags_json, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (payload.kind, payload.subject_id, payload.body,
             json.dumps(payload.tags or []), now, now),
        )
        new_id = cur.lastrowid
    return {"id": new_id, "ok": True}


@router.put("/annotations/{anno_id}")
def update_annotation(anno_id: int, payload: AnnotationUpdate):
    now = datetime.now(timezone.utc).isoformat()
    with tx() as conn:
        cur = conn.execute(
            "UPDATE annotations SET body = ?, tags_json = ?, updated_at = ? WHERE id = ?",
            (payload.body, json.dumps(payload.tags or []), now, anno_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(404, "not found")
    return {"ok": True, "updated_at": now}


@router.delete("/annotations/{anno_id}")
def delete_annotation(anno_id: int):
    with tx() as conn:
        cur = conn.execute("DELETE FROM annotations WHERE id = ?", (anno_id,))
        if cur.rowcount == 0:
            raise HTTPException(404, "not found")
    return {"ok": True}


# ----- Watchlist -----


class WatchlistIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    query: str = Field(min_length=1, max_length=200)
    kind: WatchKind = "text"
    min_priority: int = Field(default=0, ge=0, le=100)
    slack: bool = False
    enabled: bool = True


@router.get("/watchlist")
def list_watchlist():
    rows = fetchall(
        "SELECT id, name, kind, query, min_priority, enabled, slack, "
        "       created_at, last_hit, hits FROM watchlist ORDER BY id DESC"
    )
    return {"items": [dict(r) for r in rows]}


@router.post("/watchlist")
def create_watch(payload: WatchlistIn):
    now = datetime.now(timezone.utc).isoformat()
    with tx() as conn:
        try:
            cur = conn.execute(
                "INSERT INTO watchlist (name, kind, query, min_priority, enabled, slack, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (payload.name, payload.kind, payload.query, payload.min_priority,
                 1 if payload.enabled else 0, 1 if payload.slack else 0, now),
            )
        except Exception:
            # Log server-side, return a generic message — never echo internals.
            import logging as _log
            _log.getLogger("sechub.workspace").exception("watchlist insert failed")
            raise HTTPException(409, "watchlist conflict")
    return {"id": cur.lastrowid, "ok": True}


@router.delete("/watchlist/{wid}")
def delete_watch(wid: int):
    with tx() as conn:
        cur = conn.execute("DELETE FROM watchlist WHERE id = ?", (wid,))
        if cur.rowcount == 0:
            raise HTTPException(404, "not found")
    return {"ok": True}


@router.put("/watchlist/{wid}")
def update_watch(wid: int, payload: WatchlistIn):
    with tx() as conn:
        cur = conn.execute(
            "UPDATE watchlist SET name=?, kind=?, query=?, min_priority=?, enabled=?, slack=? WHERE id=?",
            (payload.name, payload.kind, payload.query, payload.min_priority,
             1 if payload.enabled else 0, 1 if payload.slack else 0, wid),
        )
        if cur.rowcount == 0:
            raise HTTPException(404, "not found")
    return {"ok": True}
