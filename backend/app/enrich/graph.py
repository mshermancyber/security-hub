"""Narrative graph builder — CVE ↔ vendor ↔ actor ↔ malware ↔ org ↔ sector."""
from __future__ import annotations

import json

from ..db import fetchall, fetchone, row_to_dict
from ..sqlutil import ESCAPE_CLAUSE, like


def narrative_graph(cve_id: str) -> dict:
    cve_id = cve_id.upper()
    cve_row = fetchone(
        "SELECT cve_id, description, cvss_score, cvss_severity, epss_score, is_kev, "
        "entities_json, priority FROM cves WHERE cve_id = ?",
        (cve_id,),
    )
    if cve_row is None:
        return {"cve": None, "nodes": [], "edges": []}
    cve = row_to_dict(cve_row)
    ents = cve.get("entities") or {}

    nodes: list[dict] = []
    edges: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, nid: str, label: str, extra: dict | None = None) -> str:
        key = (kind, nid)
        if key not in seen:
            seen.add(key)
            n = {"id": f"{kind}:{nid}", "kind": kind, "label": label}
            if extra:
                n.update(extra)
            nodes.append(n)
        return f"{kind}:{nid}"

    # Center node
    cve_node = add("cve", cve_id, cve_id, {
        "cvss": cve.get("cvss_score"),
        "epss": cve.get("epss_score"),
        "priority": cve.get("priority"),
        "is_kev": cve.get("is_kev"),
    })

    for v in ents.get("vendors") or []:
        n = add("vendor", v["id"], v["name"], {"category": v.get("category")})
        edges.append({"from": cve_node, "to": n, "kind": "affects"})
    for a in ents.get("ai_companies") or []:
        n = add("ai_company", a["id"], a["name"])
        edges.append({"from": cve_node, "to": n, "kind": "affects"})
    for o in ents.get("orgs") or []:
        n = add("org", o["id"], o["name"])
        edges.append({"from": cve_node, "to": n, "kind": "stack-exposure"})

    # Pull related news + their entities to expand the graph one hop
    news_rows = fetchall(
        f"SELECT id, source_name, title, url, priority, entities_json, tags_json "
        f"FROM news WHERE cves_json LIKE ? {ESCAPE_CLAUSE} ORDER BY priority DESC LIMIT 30",
        (f"%{like(cve_id)}%",),
    )

    # Pre-load actor → techniques map from the MITRE taxonomy for overlay.
    actor_techniques: dict[str, list[dict]] = {}
    try:
        from ..db import load_taxonomy
        for tax in ("threat_actors", "threat_actors_mitre"):
            try:
                doc = load_taxonomy(tax)
            except FileNotFoundError:
                continue
            for a in doc.get("threat_actors", []):
                if a.get("techniques"):
                    actor_techniques.setdefault(a["id"], a["techniques"])
    except Exception:
        pass

    actor_seen: set[str] = set()
    malware_seen: set[str] = set()
    sector_seen: set[str] = set()
    for r in news_rows:
        try:
            e = json.loads(r["entities_json"] or "{}")
        except Exception:
            continue
        for a in e.get("threat_actors") or []:
            if a["id"] in actor_seen:
                continue
            actor_seen.add(a["id"])
            techs = actor_techniques.get(a["id"]) or []
            n = add("actor", a["id"], a["name"], {
                "actor_type": a.get("type"), "origin": a.get("origin"),
                "techniques": techs[:6],  # top 6 for hover
            })
            edges.append({"from": cve_node, "to": n, "kind": "exploited-by"})
        for m in e.get("malware") or []:
            if m["id"] in malware_seen:
                continue
            malware_seen.add(m["id"])
            n = add("malware", m["id"], m["name"], {"malware_type": m.get("type")})
            edges.append({"from": cve_node, "to": n, "kind": "delivers"})
        for s in e.get("sectors") or []:
            if s["id"] in sector_seen:
                continue
            sector_seen.add(s["id"])
            n = add("sector", s["id"], s["name"])
            edges.append({"from": cve_node, "to": n, "kind": "targets"})

    # Add news as outer ring (limit so layout doesn't explode)
    for r in news_rows[:10]:
        n = add("news", r["id"], (r["title"] or "")[:60],
                {"source": r["source_name"], "url": r["url"], "priority": r["priority"]})
        edges.append({"from": cve_node, "to": n, "kind": "reports"})

    return {
        "cve": cve,
        "nodes": nodes,
        "edges": edges,
        "counts": {
            "vendors": sum(1 for n in nodes if n["kind"] == "vendor"),
            "actors":  sum(1 for n in nodes if n["kind"] == "actor"),
            "malware": sum(1 for n in nodes if n["kind"] == "malware"),
            "sectors": sum(1 for n in nodes if n["kind"] == "sector"),
            "orgs":    sum(1 for n in nodes if n["kind"] == "org"),
            "news":    sum(1 for n in nodes if n["kind"] == "news"),
        },
    }
