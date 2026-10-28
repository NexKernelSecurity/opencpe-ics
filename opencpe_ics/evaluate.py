"""Measure the matcher against CPEs NVD analysts wrote themselves.

Honest setup: aliases are learned only from CVEs published *before* the cutoff,
and every test CVE is excluded from training. Scoring is at vendor:product level
(the part that decides whether a scanner can match at all) plus version-bound agreement.
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

from .aliases import AliasTable
from .cpe import unescape
from .matcher import Matcher
from .normalize import norm_vendor, split_affected
from .versioncmp import ranges_agree


def truth_set(rec):
    return {(unescape(c["vendor"]), unescape(c["product"])) for c in rec["cpes"] if c["part"] in ("a", "o")}


def truth_bounds(rec):
    out = defaultdict(list)
    for c in rec["cpes"]:
        if c["part"] not in ("a", "o"):
            continue
        d = {k: v for k, v in c.items() if k.startswith("versionS") or k.startswith("versionE")}
        d["_exact"] = c.get("version")
        out[(unescape(c["vendor"]), unescape(c["product"]))].append(d)
    return out


def run(corpus: Path, ids: list[str], cutoff: str, out_csv: Path, min_conf: float = 0.0, groups=None):
    ids = set(ids)
    test = {}
    with open(corpus) as fh:
        for line in fh:
            if line[7:30].split('"')[0] not in ids:  # fast pre-filter on '{"id":"CVE-...'
                continue
            rec = json.loads(line)
            if rec["id"] in ids:
                test[rec["id"]] = rec
    aliases = AliasTable.from_corpus(corpus, before=cutoff, exclude=ids)
    m = Matcher(aliases)
    rows = []
    for cid, rec in sorted(test.items()):
        truth = truth_set(rec)
        if not truth or not rec["affected"]:
            continue
        prim, _ = split_affected(rec["affected"], rec.get("source"))
        maps = [x for x in m.map_cve(prim) if x.confidence >= min_conf]
        pred = {(x.vendor, x.product) for x in maps}
        tp = pred & truth
        tb = truth_bounds(rec)
        ver_ok = ver_tot = 0
        grouped = defaultdict(list)
        for x in maps:
            if (x.vendor, x.product) in tp:
                grouped[(x.vendor, x.product)] += [
                    dict({k: v for k, v in mm.items() if k.startswith("versionS") or k.startswith("versionE")},
                         _exact=parse_ver(mm["criteria"])) for mm in x.matches]
        for key, pm in grouped.items():
            ver_tot += 1
            ver_ok += ranges_agree(pm, tb[key])
        rows.append({"cve": cid, "group": (groups or {}).get(cid, ""), "own": is_vendor_own(rec, prim), "truth": len(truth), "pred": len(pred),
                     "tp": len(tp), "vendor_ok": bool({v for v, _ in pred} & {v for v, _ in truth}),
                     "any_ok": bool(tp), "ver_ok": ver_ok, "ver_tot": ver_tot,
                     "min_conf_pred": min((x.confidence for x in maps), default=0),
                     "levels": "|".join(sorted({x.level for x in maps})),
                     "truth_cpes": "|".join(sorted(f"{v}:{p}" for v, p in truth)),
                     "pred_cpes": "|".join(sorted(f"{x.vendor}:{x.product}({x.level})" for x in maps))})
    with open(out_csv, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    return rows, m


def vnorm(v):
    if not v:
        return v
    v = str(v).lower().lstrip("v")
    while v.endswith(".0") and v.count(".") > 1:
        v = v[:-2]
    return v.removesuffix(".0") if v.count(".") == 1 and v.endswith(".0") else v


def is_vendor_own(rec, prim):
    """True when the CNA is describing its own product (not a third-party component CVE)."""
    vendors = {norm_vendor(a.get("vendor", "")) for a in prim} - {""}
    src = (rec.get("source") or "").lower()
    if any(v and v.split()[0] in src for v in vendors):
        return True
    return src in ("ics-cert@hq.dhs.gov", "productcert@siemens.com", "psirt@us.ibm.com") and \
        not any(v in ("linux", "openssl", "apache", "gnu", "python") for v in vendors)


def parse_ver(criteria):
    from .cpe import parse_cpe
    return parse_cpe(criteria)["version"]


def summarize(rows, label=""):
    n = len(rows)
    if not n:
        return f"{label}: no rows"
    P = sum(r["pred"] for r in rows)
    T = sum(r["truth"] for r in rows)
    TP = sum(r["tp"] for r in rows)
    vt = sum(r["ver_tot"] for r in rows)
    vo = sum(r["ver_ok"] for r in rows)
    return (f"{label}: CVEs={n} | vendor correct={100*sum(r['vendor_ok'] for r in rows)/n:.1f}% | "
            f"at least one exact CPE product={100*sum(r['any_ok'] for r in rows)/n:.1f}% | "
            f"product precision={100*TP/max(P,1):.1f}% recall={100*TP/max(T,1):.1f}% | "
            f"version bound agreement={100*vo/max(vt,1):.1f}%")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus")
    ap.add_argument("ics_results_csv")
    ap.add_argument("--cutoff", default="2026-04-28")
    ap.add_argument("--out", default="evaluation.csv")
    a = ap.parse_args()
    src = list(csv.DictReader(open(a.ics_results_csv)))
    ids = [r["cve"] for r in src if int(r["nvd_cpe"]) > 0]
    groups = {r["cve"]: ("siemens" if "Siemens" in r["vendor"] else "other") for r in src}
    rows, _ = run(Path(a.corpus), ids, a.cutoff, Path(a.out), groups=groups)
    print(summarize(rows, "ALL"))
    print(summarize([r for r in rows if r["group"] == "siemens"], "Siemens"))
    print(summarize([r for r in rows if r["group"] == "other"], "Non-Siemens"))
    print(summarize([r for r in rows if r["own"]], "Vendor-own ICS CVEs (the real target)"))
    print(summarize([r for r in rows if not r["own"]], "Third-party component CVEs"))
    own = [r for r in rows if r["own"]]
    for lvl in ("high", "medium", "low"):
        print(summarize([r for r in own if r["levels"] == lvl], f"  own, only-{lvl}"))
    for lvl in ("high", "medium", "low"):
        sub = [r for r in rows if r["levels"] == lvl]
        print(summarize(sub, f"only-{lvl}"))
