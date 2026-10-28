"""Loose version comparison and range membership, good enough to compare two
descriptions of the same affected range (e.g. '<= 17.00.00' vs '< 17.00.01')."""
from __future__ import annotations

import re

_TOK = re.compile(r"\d+|[a-z]+")


def vkey(v: str):
    toks = _TOK.findall(str(v).lower().lstrip("v"))
    out = [(0, int(t)) if t.isdigit() else (-1, t) for t in toks]  # letters (rc/beta) sort before numbers
    while out and out[-1] == (0, 0):
        out.pop()
    return tuple(out)


def in_range(v: str, m: dict) -> bool:
    k = vkey(v)
    ver = m.get("_exact")
    if ver not in (None, "*", "-"):
        return k == vkey(ver)
    if m.get("versionStartIncluding") and k < vkey(m["versionStartIncluding"]):
        return False
    if m.get("versionStartExcluding") and k <= vkey(m["versionStartExcluding"]):
        return False
    if m.get("versionEndIncluding") and k > vkey(m["versionEndIncluding"]):
        return False
    if m.get("versionEndExcluding") and k >= vkey(m["versionEndExcluding"]):
        return False
    return True


def bound_versions(ms: list[dict]) -> set[str]:
    out = set()
    for m in ms:
        for key in ("_exact", "versionStartIncluding", "versionStartExcluding",
                    "versionEndIncluding", "versionEndExcluding"):
            if m.get(key) not in (None, "*", "-"):
                out.add(m[key])
    return out


def ranges_agree(pred: list[dict], truth: list[dict]) -> bool:
    """Probe every boundary version either side mentions; agree if both sides
    classify each probe (affected / not affected) the same way."""
    probes = bound_versions(pred) | bound_versions(truth)
    if not probes:
        return True  # both say 'all versions'
    for p in probes:
        if any(in_range(p, m) for m in pred) != any(in_range(p, m) for m in truth):
            return False
    return True
