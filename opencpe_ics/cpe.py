"""CPE 2.3 helpers and conversion of CVE 5.x `versions` objects into NVD-style
cpeMatch version bounds."""
from __future__ import annotations

import re
import unicodedata

CPE_FIELDS = ["cpe", "ver", "part", "vendor", "product", "version", "update", "edition",
              "language", "sw_edition", "target_sw", "target_hw", "other"]

_SPLIT = re.compile(r"(?<!\\):")


def parse_cpe(s: str) -> dict | None:
    if not s or not s.startswith("cpe:2.3:"):
        return None
    parts = _SPLIT.split(s)
    if len(parts) != 13:
        return None
    return dict(zip(CPE_FIELDS, parts))


def unescape(v: str) -> str:
    return re.sub(r"\\(.)", r"\1", v)


def escape(v: str) -> str:
    # CPE 2.3 formatted string: escape every non-alphanumeric except '_', '-', '.'
    return "".join(c if (c.isalnum() or c in "_-.") else "\\" + c for c in v)


def cpe_name(text: str) -> str:
    """Turn a human vendor/product name into CPE-style token (what NVD would write)."""
    from .normalize import strip_marks
    t = unicodedata.normalize("NFKD", strip_marks(text)).encode("ascii", "ignore").decode()
    t = t.strip().lower()
    t = re.sub(r"\(.*?\)", " ", t)              # drop "(formerly ...)", "(VDR)"
    t = re.sub(r"\s+[-\u2013]\s+", " ", t)       # "Expert - HVAC" -> "Expert HVAC"
    t = re.sub(r"\s+", "_", t)
    t = re.sub(r"[^a-z0-9_\-.+/!&()]", "", t)
    t = re.sub(r"_+", "_", t).strip("_")
    return t


def build_cpe(part: str, vendor: str, product: str, version: str = "*") -> str:
    v = escape(version) if version not in ("*", "-") else version
    return f"cpe:2.3:{part}:{escape(vendor)}:{escape(product)}:{v}:*:*:*:*:*:*:*"


# ---------------------------------------------------------------- versions

_ANY = {"", "*", "0", "n/a", "na", "-", "all", "all versions", "unspecified", "unknown"}


def clean_version(v: str | None) -> str | None:
    if v is None:
        return None
    v = str(v).strip()
    if v.lower() in _ANY:
        return None
    v = re.sub(r"^(?:version|ver\.?|rev\.?)\s*", "", v, flags=re.I)
    v = re.sub(r"^[vV](?=\d)", "", v)  # Siemens style 'V3.1' -> '3.1' (NVD convention)
    v = re.sub(r"\.[xX*]$", ".0", v)    # range start written as '7.1.x' -> '7.1.0'
    return v.strip() or None


_TEXT_RANGE = [
    # (regex, kind) ; kind tells which bound the captured version is
    (re.compile(r"^(?:all\s+versions\s*)?(?:<=|≤|up\s+to\s+and\s+including|through|up\s+to)\s*(.+)$", re.I), "le"),
    (re.compile(r"^(?:all\s+versions\s*)?(?:<|before|prior\s+to|earlier\s+than|below)\s*(.+)$", re.I), "lt"),
    (re.compile(r"^(.+?)\s+(?:and\s+(?:earlier|prior|below|older)|or\s+(?:earlier|lower|older))$", re.I), "le"),
]
_COMPOUND = re.compile(r"^\s*>=?\s*([^,<]+?)\s*,\s*(<=?)\s*(.+?)\s*$")


def versions_to_bounds(versions: list[dict] | None) -> list[dict]:
    """Return list of bound dicts: {"version": exact-or-'*', versionStart*/End* ...}.
    Each dict maps to one cpeMatch entry. Unaffected entries are skipped."""
    if not versions:
        return [{"version": "*", "_note": "no version data"}]
    if all((v.get("versionType") or "").lower() == "git" for v in versions):
        return []  # commit ranges only: nothing a CPE can express (another entry usually has semver data)
    branch = _branch_fix_bounds(versions)
    if branch is not None:
        return branch
    out = []
    for v in versions:
        if (v.get("status") or "affected").lower() != "affected":
            continue
        if (v.get("versionType") or "").lower() == "git":
            continue  # commit hashes cannot be expressed as CPE versions
        raw = str(v.get("version", "")).strip()
        lt, le = v.get("lessThan"), v.get("lessThanOrEqual")
        b: dict = {"version": "*"}
        m = _COMPOUND.match(raw)
        if m and not (lt or le):
            start, op, end = m.groups()
            if clean_version(start):
                b["versionStartIncluding"] = clean_version(start)
            if clean_version(end):
                b["versionEndExcluding" if op == "<" else "versionEndIncluding"] = clean_version(end)
            out.append(b)
            continue
        if lt or le:
            start = clean_version(raw)
            if start and start not in ("*",):
                b["versionStartIncluding"] = start
            if lt and clean_version(lt) and str(lt).strip() != "*":
                b["versionEndExcluding"] = clean_version(lt)
            elif le and clean_version(le) and str(le).strip() != "*":
                b["versionEndIncluding"] = clean_version(le)
            out.append(b)
            continue
        # free-text forms inside "version"
        matched = False
        for rx, kind in _TEXT_RANGE:
            mm = rx.match(raw)
            if mm and clean_version(mm.group(1)):
                b["versionEndExcluding" if kind == "lt" else "versionEndIncluding"] = clean_version(mm.group(1))
                out.append(b)
                matched = True
                break
        if matched:
            continue
        exact = clean_version(raw)
        if exact:
            out.append({"version": exact})
        else:
            out.append({"version": "*", "_note": "all versions"})
    return out or [{"version": "*", "_note": "no affected status"}]


_BRANCH = re.compile(r"^(\d+(?:\.\d+)*)\.\*$")


def _branch_fix_bounds(versions: list[dict]) -> list[dict] | None:
    """Handle the 'affected since X, fixed per stable branch' style used by the Linux
    kernel CNA and others:  {version: X, status: affected} plus unaffected entries
    {version: F, lessThanOrEqual: 'A.B.*'} for each branch fix.  Produces NVD-style
    ranges: [X, F1), [next(B1), F2), ...  Returns None when the pattern is absent."""
    from .versioncmp import vkey

    fixes = []  # (branch, fix)
    mainline = []
    introduced = []
    for v in versions:
        if (v.get("versionType") or "").lower() == "git":
            continue
        st = (v.get("status") or "affected").lower()
        ver = clean_version(v.get("version"))
        le = str(v.get("lessThanOrEqual") or "")
        if st == "unaffected" and ver:
            m = _BRANCH.match(le)
            if m:
                fixes.append((m.group(1), ver))
            elif le == "*" and not v.get("lessThan"):
                mainline.append(ver)
            elif v.get("lessThan") and str(v.get("version")).strip() in ("0", "*"):
                introduced.append(clean_version(v["lessThan"]))
        elif st == "affected" and ver and not v.get("lessThan") and not v.get("lessThanOrEqual"):
            introduced.append(ver)
    if not fixes:
        return None
    start = min(introduced, key=vkey) if introduced else None
    fixes.sort(key=lambda bf: vkey(bf[0]))
    out, prev_branch = [], None
    for br, fix in fixes:
        lo = start if prev_branch is None else _next_minor(prev_branch)
        if lo and start and vkey(lo) < vkey(start):
            lo = start
        if lo and vkey(fix) <= vkey(lo):
            prev_branch = br
            continue
        b = {"version": "*", "versionEndExcluding": fix}
        if lo:
            b["versionStartIncluding"] = lo
        out.append(b)
        prev_branch = br
    if mainline:
        fix = min(mainline, key=vkey)
        lo = _next_minor(prev_branch)
        if vkey(fix) > vkey(lo):
            out.append({"version": "*", "versionStartIncluding": lo, "versionEndExcluding": fix})
    return out or None


def _next_minor(branch: str) -> str:
    parts = branch.split(".")
    if len(parts) >= 2 and parts[1].isdigit():
        return f"{parts[0]}.{int(parts[1]) + 1}"
    return f"{int(parts[0]) + 1}" if parts[0].isdigit() else branch
