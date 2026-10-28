"""opencpe-ics command line.

  opencpe-ics corpus   CVE-all.json.xz corpus.jsonl
  opencpe-ics learn    corpus.jsonl aliases.json
  opencpe-ics gap      --csaf CSAF/csaf_files/OT/white --anchore nvd-data-overrides --corpus corpus.jsonl
  opencpe-ics enrich   --corpus corpus.jsonl --aliases aliases.json --cves gap.csv --out out/
  opencpe-ics evaluate corpus.jsonl gap.csv
"""
from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from datetime import date, timedelta
from pathlib import Path


def main(argv=None):
    ap = argparse.ArgumentParser(prog="opencpe-ics", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("corpus", help="compact the fkie-cad NVD archive")
    p.add_argument("archive"); p.add_argument("out")

    p = sub.add_parser("learn", help="learn CNA->CPE aliases from NVD history")
    p.add_argument("corpus"); p.add_argument("out"); p.add_argument("--before")

    p = sub.add_parser("gap", help="list CISA ICS CVEs with no CPE anywhere")
    p.add_argument("--csaf", required=True); p.add_argument("--anchore", required=True)
    p.add_argument("--corpus", required=True); p.add_argument("--out", default="gap.csv")
    p.add_argument("--since", default=str(date.today() - timedelta(days=183)))
    p.add_argument("--until", default=str(date.today()))

    p = sub.add_parser("enrich", help="generate CPE enrichment for CVEs")
    p.add_argument("--corpus", required=True); p.add_argument("--aliases", required=True)
    p.add_argument("--cves", required=True, help="CSV with a 'cve' column (rows with gap=False are skipped) or one CVE per line")
    p.add_argument("--out", default="out"); p.add_argument("--min-level", default="medium", choices=["low", "medium", "high"])

    p = sub.add_parser("evaluate", help="measure accuracy against NVD-analysed CVEs")
    p.add_argument("corpus"); p.add_argument("gap_csv"); p.add_argument("--cutoff", required=True)
    p.add_argument("--out", default="evaluation.csv")

    a = ap.parse_args(argv)

    if a.cmd == "corpus":
        from .corpus import build_corpus
        print(f"{build_corpus(Path(a.archive), Path(a.out))} CVE records written")
    elif a.cmd == "learn":
        from .aliases import AliasTable
        t = AliasTable.from_corpus(Path(a.corpus), before=a.before)
        t.save(Path(a.out))
        print(f"{len(t.vendor)} vendor aliases, {len(t.product)} product aliases")
    elif a.cmd == "gap":
        from .gap import anchore_ids, find_gap, ics_cves
        cves = ics_cves(Path(a.csaf), a.since, a.until)
        rows = find_gap(Path(a.corpus), cves, anchore_ids(Path(a.anchore)), Path(a.out))
        n, g = len(rows), sum(r["gap"] for r in rows)
        print(f"{n} ICS CVEs ({a.since}..{a.until}); {g} ({100*g/max(n,1):.1f}%) have no CPE anywhere -> {a.out}")
    elif a.cmd == "enrich":
        from .aliases import AliasTable
        from .enrich import enrich
        from .matcher import Matcher
        ids = _read_ids(Path(a.cves))
        out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
        summary = enrich(Path(a.corpus), Matcher(AliasTable.load(Path(a.aliases))), ids, out, a.min_level)
        print(Counter(s["outcome"] for s in summary).most_common())
        print("best level per CVE:", Counter(s["level"] for s in summary if s["level"]).most_common())
    elif a.cmd == "evaluate":
        from .evaluate import run, summarize
        src = list(csv.DictReader(open(a.gap_csv)))
        ids = [r["cve"] for r in src if int(r["nvd_cpe"]) > 0]
        rows, _ = run(Path(a.corpus), ids, a.cutoff, Path(a.out))
        print(summarize(rows, "ALL"))
        own = [r for r in rows if r["own"]]
        print(summarize(own, "Vendor-own CVEs"))
        for lvl in ("high", "medium", "low"):
            print(summarize([r for r in own if r["levels"] == lvl], f"  only-{lvl}"))


def _read_ids(path: Path) -> list[str]:
    txt = path.read_text()
    if txt.startswith("cve") or "," in txt.splitlines()[0]:
        rows = list(csv.DictReader(txt.splitlines()))
        key = "gap" if "gap" in rows[0] else ("any_cpe" if "any_cpe" in rows[0] else None)
        if key == "gap":
            return [r["cve"] for r in rows if r["gap"] in ("True", "true", "1")]
        if key == "any_cpe":
            return [r["cve"] for r in rows if r["any_cpe"] in ("False", "false", "0")]
        return [r["cve"] for r in rows]
    return [l.strip() for l in txt.splitlines() if l.strip().startswith("CVE-")]


if __name__ == "__main__":
    sys.exit(main())
