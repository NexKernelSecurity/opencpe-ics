"""Find the CPE gap: CVEs from CISA ICS advisories (CSAF) that have no CPE in NVD,
in the CNA/ADP record, or in Anchore's nvd-data-overrides."""
from __future__ import annotations

import csv
import glob
import json
import os
import subprocess
from pathlib import Path


def ics_cves(csaf_dir: Path, since: str, until: str) -> dict[str, dict]:
    """csaf_dir = checkout of cisagov/CSAF at csaf_files/OT/white."""
    out: dict[str, dict] = {}
    for f in sorted(glob.glob(str(csaf_dir / "*" / "*.json"))):
        try:
            d = json.load(open(f))
        except (ValueError, OSError):
            continue
        t = d.get("document", {}).get("tracking", {})
        rel = (t.get("initial_release_date") or "")[:10]
        if not (since <= rel <= until):
            continue
        vendors = set()

        def walk(n):
            if isinstance(n, dict):
                if n.get("category") == "vendor" and n.get("name"):
                    vendors.add(n["name"])
                for v in n.values():
                    walk(v)
            elif isinstance(n, list):
                for v in n:
                    walk(v)
        walk(d.get("product_tree", {}))
        for v in d.get("vulnerabilities", []):
            c = v.get("cve")
            if not c:
                continue
            rec = out.setdefault(c, {"advisories": set(), "vendors": set(), "released": rel})
            rec["advisories"].add(t.get("id"))
            rec["vendors"] |= vendors
            rec["released"] = min(rec["released"], rel)
    return out


def anchore_ids(anchore_repo: Path) -> set[str]:
    names = subprocess.run(["git", "-C", str(anchore_repo), "ls-tree", "-r", "--name-only", "HEAD"],
                           capture_output=True, text=True, check=True).stdout.split()
    return {os.path.basename(n)[:-5] for n in names if n.startswith("data/") and n.endswith(".json")}


def find_gap(corpus: Path, cves: dict[str, dict], anchore: set[str], out_csv: Path) -> list[dict]:
    rows = {}
    with open(corpus) as fh:
        for line in fh:
            cid = line[7:30].split('"')[0]
            if cid not in cves:
                continue
            rec = json.loads(line)
            nvd_cpe = sum(1 for c in rec["cpes"] if c["part"] in ("a", "o"))
            cna_cpe = sum(len(a.get("cpes") or []) for a in rec["affected"])
            rows[cid] = {"cve": cid, "status": rec["status"], "nvd_cpe": nvd_cpe, "cna_cpe": cna_cpe,
                         "in_anchore": cid in anchore}
    result = []
    for cid, meta in sorted(cves.items()):
        r = rows.get(cid, {"cve": cid, "status": "NOT_IN_NVD", "nvd_cpe": 0, "cna_cpe": 0, "in_anchore": cid in anchore})
        r.update(released=meta["released"], vendor="|".join(sorted(meta["vendors"])),
                 advisories="|".join(sorted(meta["advisories"])))
        r["gap"] = not (r["nvd_cpe"] or r["cna_cpe"] or r["in_anchore"])
        result.append(r)
    with open(out_csv, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(result[0]))
        w.writeheader()
        w.writerows(result)
    return result
