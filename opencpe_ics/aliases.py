"""Learn how NVD analysts have historically translated CNA vendor/product strings
into CPE vendor/product tokens. Every learned alias keeps example CVE IDs, so each
later mapping can cite the historical evidence it is based on."""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from rapidfuzz import fuzz

from .cpe import unescape
from .normalize import cpe_product_key, norm_product, norm_vendor, split_affected

MAX_EXAMPLES = 3


class AliasTable:
    def __init__(self):
        self.vendor = defaultdict(Counter)            # norm cna vendor -> Counter(cpe vendor)
        self.product = defaultdict(Counter)           # (cpe vendor, norm cna product) -> Counter((part, cpe product))
        self.vendor_products = defaultdict(Counter)   # cpe vendor -> Counter((part, cpe product))
        self.examples = defaultdict(list)             # key -> [cve ids]
        self.cpe_vendors = Counter()
        self.last_seen = {}                           # key -> latest publish date seen

    # ------------------------------------------------------------ learning
    def _ex(self, key, cve, date=""):
        if date > self.last_seen.get(key, ""):
            self.last_seen[key] = date
        lst = self.examples[key]
        if len(lst) < MAX_EXAMPLES and cve not in lst:
            lst.append(cve)

    def learn(self, rec: dict) -> None:
        cpes = [c for c in rec.get("cpes", []) if c["part"] in ("a", "o")]
        if not cpes:
            return
        for c in cpes:
            v, p = unescape(c["vendor"]), unescape(c["product"])
            self.cpe_vendors[v] += 1
            self.vendor_products[v][(c["part"], p)] += 1
        prim, _ = split_affected(rec.get("affected", []), rec.get("source"))
        aff = [a for a in prim if a.get("vendor") and a.get("product")]
        if not aff:
            return
        cpe_vendors = {unescape(c["vendor"]) for c in cpes}
        cna_vendors = {norm_vendor(a["vendor"]) for a in aff} - {""}
        # vendor alias: unambiguous when both sides name a single vendor
        if len(cpe_vendors) == 1 and len(cna_vendors) == 1:
            nv, cv = next(iter(cna_vendors)), next(iter(cpe_vendors))
            self.vendor[nv][cv] += 1
            self._ex(("v", nv, cv), rec["id"], rec.get("published", ""))
        # product alias
        by_vendor = defaultdict(set)
        for c in cpes:
            by_vendor[unescape(c["vendor"])].add((c["part"], unescape(c["product"])))
        for a in aff:
            np_ = norm_product(a["product"])
            if not np_:
                continue
            nv = norm_vendor(a["vendor"])
            target_vendors = [cv for cv in by_vendor
                              if len(cpe_vendors) == 1 or fuzz.token_set_ratio(nv, cv.replace("_", " ")) >= 80]
            for cv in target_vendors:
                prods = by_vendor[cv]
                if len(aff) == 1:
                    chosen = prods
                else:
                    scored = [(fuzz.token_set_ratio(np_, cpe_product_key(p)), (pt, p)) for pt, p in prods]
                    best = max(s for s, _ in scored)
                    chosen = {x for s, x in scored if s >= max(70, best - 5)}
                for x in chosen:
                    self.product[(cv, np_)][x] += 1
                    self._ex(("p", cv, np_, x), rec["id"], rec.get("published", ""))

    # ------------------------------------------------------------ io
    @classmethod
    def from_corpus(cls, path: Path, before: str | None = None, exclude: set[str] | None = None):
        t = cls()
        with open(path) as fh:
            for line in fh:
                rec = json.loads(line)
                if before and rec["published"] >= before:
                    continue
                if exclude and rec["id"] in exclude:
                    continue
                t.learn(rec)
        return t

    def save(self, path: Path) -> None:
        data = {
            "vendor": {k: dict(v) for k, v in self.vendor.items()},
            "product": [[k[0], k[1], [[pt, p, n] for (pt, p), n in v.items()]] for k, v in self.product.items()],
            "vendor_products": {k: [[pt, p, n] for (pt, p), n in v.items()] for k, v in self.vendor_products.items()},
            "examples": [[list(k[:3]) + ([list(k[3])] if len(k) > 3 else []), v] for k, v in self.examples.items()],
            "cpe_vendors": dict(self.cpe_vendors),
            "last_seen": [[list(k[:3]) + ([list(k[3])] if len(k) > 3 else []), v] for k, v in self.last_seen.items()],
        }
        with open(path, "w") as fh:
            json.dump(data, fh)

    @classmethod
    def load(cls, path: Path):
        t = cls()
        d = json.load(open(path))
        for k, v in d["vendor"].items():
            t.vendor[k] = Counter(v)
        for cv, np_, lst in d["product"]:
            t.product[(cv, np_)] = Counter({(pt, p): n for pt, p, n in lst})
        for k, lst in d["vendor_products"].items():
            t.vendor_products[k] = Counter({(pt, p): n for pt, p, n in lst})
        for k, v in d["examples"]:
            key = tuple(k[:3]) + ((tuple(k[3]),) if len(k) > 3 else ())
            t.examples[key] = v
        t.cpe_vendors = Counter(d["cpe_vendors"])
        for k, v in d.get("last_seen", []):
            t.last_seen[tuple(k[:3]) + ((tuple(k[3]),) if len(k) > 3 else ())] = v
        return t

    def recency_weighted(self, prefix: tuple, hist: Counter) -> dict:
        """Down-weight spellings NVD stopped using: each year older than the most
        recent spelling halves an alias's weight (vendors rename; NVD follows)."""
        dates = {x: self.last_seen.get(prefix + (x,), "") for x in hist}
        newest = max(dates.values(), default="")
        out = {}
        for x, n in hist.items():
            d = dates[x]
            years = (int(newest[:4]) - int(d[:4])) if (newest and d) else 0
            out[x] = n * (0.5 ** max(0, years))
        return out
