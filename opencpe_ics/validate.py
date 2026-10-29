"""Check human-reviewed records before they are merged.

    python -m opencpe_ics.validate data/reviewed
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from .cpe import parse_cpe

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_BOUNDS = {"versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"}
REQUIRED_ANNOTATION = ("cve_id", "reviewed_by", "review_sources")


def check_file(path: Path) -> list[str]:
    errs = []
    cid = path.stem
    if not _CVE.match(cid):
        return [f"file name '{path.name}' is not CVE-YYYY-NNNN.json"]
    if path.parent.name != cid.split("-")[1]:
        errs.append(f"must be in folder {cid.split('-')[1]}/")
    try:
        d = json.loads(path.read_text())
    except ValueError as e:
        return errs + [f"not valid JSON: {e}"]
    ann = d.get("_annotation", {})
    for k in REQUIRED_ANNOTATION:
        if not ann.get(k):
            errs.append(f"_annotation.{k} is missing")
    if ann.get("cve_id") and ann["cve_id"] != cid:
        errs.append(f"_annotation.cve_id '{ann['cve_id']}' does not match file name")
    if ann.get("review_sources") and not all(str(u).startswith("https://") for u in ann["review_sources"]):
        errs.append("review_sources must be https:// links to the advisory or NVD CPE dictionary")
    try:
        matches = [m for c in d["cve"]["configurations"] for n in c["nodes"] for m in n["cpeMatch"]]
    except (KeyError, TypeError):
        return errs + ["cve.configurations[].nodes[].cpeMatch[] structure is missing"]
    if not matches:
        errs.append("no cpeMatch entries")
    for i, m in enumerate(matches):
        p = parse_cpe(m.get("criteria", ""))
        if not p:
            errs.append(f"cpeMatch[{i}]: '{m.get('criteria')}' is not a CPE 2.3 string with 13 fields")
            continue
        if p["part"] not in ("a", "o", "h"):
            errs.append(f"cpeMatch[{i}]: part must be a, o or h")
        if "vulnerable" not in m:
            errs.append(f"cpeMatch[{i}]: 'vulnerable' is missing")
        extra = set(m) - _BOUNDS - {"vulnerable", "criteria", "matchCriteriaId"}
        if extra:
            errs.append(f"cpeMatch[{i}]: unknown keys {sorted(extra)}")
        if p["version"] not in ("*", "-") and _BOUNDS & set(m):
            errs.append(f"cpeMatch[{i}]: use either an exact version in the CPE or version bounds, not both")
    return errs


def main(argv=None) -> int:
    root = Path((argv or sys.argv[1:] or ["data/reviewed"])[0])
    files = sorted(root.glob("*/*.json"))
    bad = 0
    for f in files:
        errs = check_file(f)
        if errs:
            bad += 1
            print(f"FAIL {f}")
            for e in errs:
                print(f"     - {e}")
    print(f"{len(files) - bad}/{len(files)} reviewed records valid")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
