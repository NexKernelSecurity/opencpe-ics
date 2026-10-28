"""Stream the full NVD JSON corpus (fkie-cad/nvd-json-data-feeds CVE-all.json.xz)
into a compact JSONL file holding only what OpenCPE-ICS needs:

    {"id", "published", "status", "source", "affected": [...CNA affected...],
     "cpes": [{"part","vendor","product","criteria", version bounds...}]}

The full corpus is ~3 GB uncompressed, so it is parsed as a stream.
"""
from __future__ import annotations

import json
import lzma
import sys
from pathlib import Path

import ijson

from .cpe import parse_cpe


def _cpes_from_configurations(configs) -> list[dict]:
    out = []
    for cfg in configs or []:
        for node in cfg.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                if not m.get("vulnerable", False):
                    continue
                p = parse_cpe(m.get("criteria", ""))
                if not p:
                    continue
                rec = {"part": p["part"], "vendor": p["vendor"], "product": p["product"],
                       "version": p["version"], "criteria": m["criteria"]}
                for k in ("versionStartIncluding", "versionStartExcluding",
                          "versionEndIncluding", "versionEndExcluding"):
                    if m.get(k):
                        rec[k] = m[k]
                out.append(rec)
    return out


def _affected(item) -> list[dict]:
    out = []
    for block in item.get("affected", []) or []:
        src = block.get("source")
        for a in block.get("affectedData", []) or []:
            rec = {k: a.get(k) for k in ("vendor", "product", "versions", "cpes",
                                         "defaultStatus", "platforms") if a.get(k)}
            rec["source"] = src
            out.append(rec)
    return out


def build_corpus(archive: Path, out_path: Path) -> int:
    n = 0
    opener = lzma.open if str(archive).endswith(".xz") else open
    with opener(archive, "rb") as fh, open(out_path, "w") as out:
        for item in ijson.items(fh, "cve_items.item", use_float=True):
            rec = {
                "id": item["id"],
                "published": (item.get("published") or "")[:10],
                "status": item.get("vulnStatus"),
                "source": item.get("sourceIdentifier"),
                "affected": _affected(item),
                "cpes": _cpes_from_configurations(item.get("configurations")),
            }
            out.write(json.dumps(rec, separators=(",", ":")) + "\n")
            n += 1
    return n


if __name__ == "__main__":
    print(build_corpus(Path(sys.argv[1]), Path(sys.argv[2])))
