"""Name normalisation used for alias learning and matching."""
from __future__ import annotations

import re
import unicodedata

_CORP = re.compile(
    r"\b(inc|incorporated|corp|corporation|co|company|ltd|limited|llc|gmbh|ag|sa|s\.a|plc|"
    r"bv|b\.v|nv|oy|ab|as|srl|spa|kg|se|pty|pte|kk|group|holdings?|technologies|technology|"
    r"tech|systems?|solutions?|industries|international|intl|electronics?|"
    r"operating as|the)\b\.?", re.I)


_MARKS = re.compile(r"[\u00ae\u2122\u00a9\u2120]|\((?:tm|r|c)\)", re.I)  # ® ™ © ℠ (TM) (R)


def strip_marks(s: str) -> str:
    return _MARKS.sub("", s or "")


def ascii_lower(s: str) -> str:
    s = unicodedata.normalize("NFKD", strip_marks(s)).encode("ascii", "ignore").decode()
    return s.lower()


def norm_vendor(s: str) -> str:
    s = ascii_lower(s)
    s = re.sub(r"\(.*?\)", " ", s)          # "(operating as Mira)" etc.
    s = re.sub(r"[^a-z0-9 ]+", " ", s)
    s = _CORP.sub(" ", s)
    return re.sub(r"\s+", " ", s).strip()


def norm_product(s: str) -> str:
    s = ascii_lower(s)
    s = re.sub(r"[®™©]", "", s)
    s = re.sub(r"[_/,;:]+", " ", s)
    s = re.sub(r"[^a-z0-9.+\- ]+", " ", s)
    s = re.sub(r"\b(firmware|software|series|family|module|devices?|products?|the)\b", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def cpe_product_key(cpe_product: str) -> str:
    """Comparable form of an existing CPE product token."""
    s = cpe_product.replace("\\", "")
    s = re.sub(r"_firmware$", "", s)
    return norm_product(s.replace("_", " "))


def split_affected(affected: list[dict], primary_source: str | None):
    """Split affected entries into those written by the CVE's own CNA and those added
    by others (e.g. a vendor PSIRT listing its products that embed a third-party library).
    Falls back to 'all primary' when sources are missing or none match."""
    prim = [a for a in affected if a.get("source") == primary_source]
    if not prim:
        return list(affected), []
    return prim, [a for a in affected if a.get("source") != primary_source]
