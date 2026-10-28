"""Produce enrichment records for a list of CVEs.

High/medium-confidence mappings go to `feed/` in the same shape as
anchore/nvd-data-overrides (so vunnel/Grype-style consumers can read them);
low-confidence mappings go to `review/` for a human to confirm via pull request.
"""
from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .matcher import Matcher
from .normalize import split_affected

LEVEL_RANK = {"low": 0, "medium": 1, "high": 2}


def record(cid: str, rec: dict, maps, generated: str) -> dict:
    cpe_match = []
    for m in maps:
        for mm in m.matches:
            mm = {k: v for k, v in mm.items() if not k.startswith("_")}
            cpe_match.append(mm)
    return {
        "_annotation": {
            "cve_id": cid,
            "generated_by": f"opencpe-ics {__version__}",
            "generated": generated,
            "reason": "Added CPE configurations because NVD has not provided them "
                      f"(NVD status: {rec.get('status')}).",
            "source_cna": rec.get("source"),
            "mappings": [{
                "cna_vendor": m.cna_vendor, "cna_product": m.cna_product,
                "cpe": f"{m.part}:{m.vendor}:{m.product}", "confidence": m.confidence,
                "level": m.level, "method": m.method, "evidence": m.evidence,
                "version_notes": sorted({x["_note"] for x in m.matches if x.get("_note")}),
            } for m in maps],
        },
        "cve": {"configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": cpe_match}]}]},
    }


def enrich(corpus: Path, matcher: Matcher, cve_ids: list[str], out_dir: Path, min_level: str = "medium"):
    want = set(cve_ids)
    recs = {}
    with open(corpus) as fh:
        for line in fh:
            cid = line[7:30].split('"')[0]
            if cid in want:
                recs[cid] = json.loads(line)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    summary = []
    for cid in sorted(want):
        rec = recs.get(cid)
        if not rec:
            summary.append({"cve": cid, "outcome": "not in NVD corpus", "level": "", "cpes": ""})
            continue
        prim, _ = split_affected(rec["affected"], rec.get("source"))
        maps = matcher.map_cve(prim)
        if not maps:
            summary.append({"cve": cid, "outcome": "no usable vendor/product in CNA data", "level": "", "cpes": ""})
            continue
        good = [m for m in maps if LEVEL_RANK[m.level] >= LEVEL_RANK[min_level]]
        weak = [m for m in maps if LEVEL_RANK[m.level] < LEVEL_RANK[min_level]]
        year = cid.split("-")[1]
        for sub, ms in (("feed", good), ("review", weak)):
            if ms:
                p = out_dir / sub / year / f"{cid}.json"
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(json.dumps(record(cid, rec, ms, generated), indent=2) + "\n")
        summary.append({"cve": cid, "outcome": "feed" if good else "review",
                        "level": max((m.level for m in maps), key=LEVEL_RANK.get),
                        "cpes": "|".join(sorted({f"{m.part}:{m.vendor}:{m.product}({m.level})" for m in maps}))})
    with open(out_dir / "summary.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["cve", "outcome", "level", "cpes"])
        w.writeheader()
        w.writerows(summary)
    return summary
