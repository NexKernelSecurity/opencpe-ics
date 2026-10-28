"""Turn the CNA `affected` block of a CVE into NVD-style CPE match criteria,
each with a confidence score and a human-readable evidence trail."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from rapidfuzz import fuzz, process

from .aliases import AliasTable
from .cpe import build_cpe, cpe_name, escape, parse_cpe, unescape, versions_to_bounds
from .normalize import cpe_product_key, norm_product, norm_vendor


@dataclass
class Mapping:
    cna_vendor: str
    cna_product: str
    part: str
    vendor: str
    product: str
    confidence: float
    method: str
    evidence: list[str] = field(default_factory=list)
    matches: list[dict] = field(default_factory=list)

    @property
    def level(self) -> str:
        return "high" if self.confidence >= 0.85 else "medium" if self.confidence >= 0.6 else "low"


class Matcher:
    def __init__(self, aliases: AliasTable):
        self.a = aliases
        self._vendor_choices = {v.replace("_", " "): v for v in aliases.cpe_vendors}
        self._squashed = {re.sub(r"[_\-. ]", "", v): v for v in aliases.cpe_vendors}

    # ---------------------------------------------------------------- vendor
    def resolve_vendor(self, cna_vendor: str):
        nv = norm_vendor(cna_vendor)
        if not nv:
            return None, 0.0, "empty vendor", []
        hist = self.a.vendor.get(nv)
        if hist:
            w = self.a.recency_weighted(("v", nv), hist)
            cv = max(w, key=w.get)
            n = hist[cv]
            share = w[cv] / sum(w.values())
            conf = min(1.0, 0.55 + 0.1 * min(n, 4)) * (0.5 + 0.5 * share)
            ex = self.a.examples.get(("v", nv, cv), [])
            return cv, conf, f"vendor '{cna_vendor}' was written as '{cv}' by NVD in {n} of {sum(hist.values())} past CVEs", ex
        direct = cpe_name(nv)
        if direct in self.a.cpe_vendors:
            return direct, 0.85, f"vendor token '{direct}' already exists in NVD ({self.a.cpe_vendors[direct]} CPE uses)", []
        squashed = nv.replace(" ", "")
        if squashed in self.a.cpe_vendors:
            return squashed, 0.8, f"vendor token '{squashed}' already exists in NVD ({self.a.cpe_vendors[squashed]} CPE uses)", []
        best = process.extractOne(nv, list(self._vendor_choices), scorer=fuzz.token_sort_ratio)
        if best and best[1] >= 92:
            cv = self._vendor_choices[best[0]]
            return cv, 0.7, f"vendor '{cna_vendor}' fuzzy-matches existing NVD vendor '{cv}' (score {best[1]:.0f})", []
        best = process.extractOne(squashed, list(self._squashed), scorer=fuzz.ratio)
        if best and best[1] >= 90 and len(squashed) >= 6:
            cv = self._squashed[best[0]]
            return cv, 0.6, f"vendor '{cna_vendor}' closely matches existing NVD vendor '{cv}' (spelling score {best[1]:.0f})", []
        return cpe_name(cna_vendor_short(cna_vendor)), 0.35, f"new vendor token derived from CNA text '{cna_vendor}'", []

    # ---------------------------------------------------------------- product
    def resolve_product(self, cv: str, cna_product: str):
        np_ = norm_product(cna_product)
        hist = self.a.product.get((cv, np_))
        if hist:
            w = self.a.recency_weighted(("p", cv, np_), hist)
            total = sum(w.values())
            top_w = max(w.values())
            picks = [(x, hist[x]) for x in hist if w[x] >= top_w * 0.5]
            out = []
            for (pt, p), n in picks:
                share = w[(pt, p)] / total
                conf = min(1.0, 0.6 + 0.1 * min(n, 4)) * (0.6 + 0.4 * share)
                ex = self.a.examples.get(("p", cv, np_, (pt, p)), [])
                out.append((pt, p, conf, f"product '{cna_product}' was written as '{p}' by NVD in {n} past CVE(s)", ex, "alias"))
            return out
        known = self.a.vendor_products.get(cv)
        if known:
            keys = {}
            for (pt, p), n in known.items():
                keys.setdefault(cpe_product_key(p), []).append((pt, p, n))
            best = process.extract(np_, list(keys), scorer=fuzz.token_sort_ratio, limit=3)
            if best and best[0][1] >= 90:
                k, score, _ = best[0]
                out = []
                for pt, p, n in keys[k]:
                    conf = 0.55 + 0.35 * (score - 90) / 10
                    out.append((pt, p, conf, f"product '{cna_product}' fuzzy-matches existing CPE '{p}' (score {score:.0f}, {n} prior uses)", [], "fuzzy"))
                return out
            part = guess_part(cna_product, known)
        else:
            part = guess_part(cna_product, None)
        prod = cpe_name(trim_descriptors(strip_vendor_prefix(cna_product, cv)))
        if part == "o" and not prod.endswith("_firmware"):
            prod += "_firmware"
        return [(part, prod, 0.3, f"new product token derived from CNA text '{cna_product}' (no NVD precedent)", [], "derived")]

    def _from_cna_cpe(self, v, p, pc, bounds) -> "Mapping":
        """CNAs sometimes invent their own CPE spelling ('palo_alto_networks' where NVD
        has always used 'paloaltonetworks'). Check the CNA's CPE against NVD vocabulary
        and correct the vendor token when the history is unambiguous."""
        cv, cp = unescape(pc["vendor"]), unescape(pc["product"])
        ev = [f"CPE supplied by the CNA in the CVE record ({pc['vendor']}:{pc['product']})"]
        conf, method = 0.95, "cna-supplied"
        alt, vconf, vev, vex = self.resolve_vendor(v)
        rare = self.a.cpe_vendors.get(cv, 0) * 10 < self.a.cpe_vendors.get(alt, 0)
        if cv not in self.a.cpe_vendors or (alt and alt != cv and vconf >= 0.85 and rare):
            if alt and alt != cv and vconf >= 0.85:
                ev.append(f"vendor token corrected to NVD's '{alt}': {vev}" + (f" (e.g. {', '.join(vex)})" if vex else ""))
                cv, conf, method = alt, 0.9, "cna-supplied, vendor corrected"
            else:
                conf = 0.7
                ev.append(f"vendor token '{cv}' has never been used by NVD")
        if (pc["part"], cp) not in self.a.vendor_products.get(cv, {}):
            conf = min(conf, 0.7)
            ev.append(f"product token '{cp}' has no NVD precedent for vendor '{cv}'")
        m = Mapping(v, p, pc["part"], cv, cp, conf, method, ev)
        if pc["version"] not in ("*", "-", ""):
            # the CNA named an exact version (and maybe update, e.g. PAN-OS 11.2.4:h3): keep it verbatim
            fields = [pc[k] for k in ("cpe", "ver", "part")] + [escape(cv)] + \
                     [pc[k] for k in ("product", "version", "update", "edition", "language",
                                      "sw_edition", "target_sw", "target_hw", "other")]
            m.matches = [{"vulnerable": True, "criteria": ":".join(fields)}]
        else:
            m.matches = _matches(m, bounds)
        return m

    # ---------------------------------------------------------------- cve
    def map_cve(self, affected: list[dict]) -> list[Mapping]:
        results: list[Mapping] = []
        for a in affected:
            v, p = a.get("vendor") or "", a.get("product") or ""
            if not v or not p or v.lower() in ("n/a", "unknown"):
                continue
            bounds = versions_to_bounds(a.get("versions"))
            if not bounds:
                continue
            if a.get("cpes"):  # the CNA already supplied CPEs: use them verbatim
                for c in a["cpes"]:
                    pc = parse_cpe(c)
                    if pc:
                        results.append(self._from_cna_cpe(v, p, pc, bounds))
                continue
            cv, vconf, vev, vex = self.resolve_vendor(v)
            if not cv:
                continue
            for pt, prod, pconf, pev, pex, method in self.resolve_product(cv, p):
                ev = [vev + (f" (e.g. {', '.join(vex)})" if vex else ""),
                      pev + (f" (e.g. {', '.join(pex)})" if pex else "")]
                m = Mapping(v, p, pt, cv, prod, round(vconf * pconf if method != "alias" else min(vconf, pconf) * 0.98 + 0.02, 3),
                            method, ev)
                m.matches = _matches(m, bounds)
                _penalise_unknown_versions(m)
                results.append(m)
        return results


_UNKNOWN_NOTES = {"no version data", "no affected status"}


def _penalise_unknown_versions(m: Mapping) -> None:
    """A CPE with no usable version bound would flag every version of the product.
    That is a false-positive risk, so such mappings are pushed down to human review."""
    if any(x.get("_note") in _UNKNOWN_NOTES for x in m.matches):
        m.confidence = round(min(m.confidence, 0.55), 3)
        m.evidence.append("version range could not be derived from the CNA data; needs human review")


def _matches(m: Mapping, bounds: list[dict]) -> list[dict]:
    out = []
    for b in bounds:
        ver = b.get("version", "*")
        rec = {"vulnerable": True, "criteria": build_cpe(m.part, m.vendor, m.product, ver)}
        for k in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"):
            if b.get(k):
                rec[k] = b[k]
        if b.get("_note"):
            rec["_note"] = b["_note"]
        out.append(rec)
    return out


_DEVICE_WORDS = ("firmware", "plc", "rtu", "hmi", "controller", "gateway", "router", "switch", "camera",
                 "relay", "cpu", "module", "inverter", "meter", "panel", "drive", "ied", "device", "sensor",
                 "station", "ups", "terminal", "dvr", "nvr", "series", "scalance", "simatic", "ruggedcom")


_SOFTWARE_WORDS = ("software", "studio", "designer", "suite", "manager", "client", "app", "portal", "tool",
                   "viewer", "editor", "library", "sdk", "toolkit", "server", "service", "web", "cloud",
                   "historian", "engineering", "workbench", "framework", "plugin", "driver", "opc")


def guess_part(product: str, vendor_history) -> str:
    """'o' (firmware/OS) or 'a' (application). Explicit software wording wins; device
    wording or a model number means firmware, if this vendor has firmware CPEs at all."""
    n = product.lower()
    if "firmware" not in n and any(re.search(rf"\b{w}", n) for w in _SOFTWARE_WORDS):
        return "a"
    device = "firmware" in n or _looks_like_device(product)
    if vendor_history:
        parts = {pt for pt, _ in vendor_history}
        if device and "o" in parts:
            return "o"
        return "a" if "a" in parts else next(iter(parts))
    return "o" if device else "a"


_MODEL_NO = re.compile(r"\b(?:[a-z]{1,6}-?\d{2,5}[a-z]{0,3}|\d{1,2}[a-z]{1,3}\d{1,4}[a-z]?)\b", re.I)


def _looks_like_device(name: str) -> bool:
    n = name.lower()
    return any(w in n for w in _DEVICE_WORDS) or bool(_MODEL_NO.search(n))


def cna_vendor_short(v: str) -> str:
    nv = norm_vendor(v)
    return nv or v


def strip_vendor_prefix(product: str, cpe_vendor: str) -> str:
    vtoks = cpe_vendor.replace("_", " ").split()
    p = product.strip()
    low = p.lower()
    for i in range(len(vtoks), 0, -1):
        pref = " ".join(vtoks[:i])
        if low.startswith(pref + " "):
            rest = p[len(pref):].strip()
            # keep the vendor word when the remainder is only a number/version ("Camunda 7")
            return rest if len(rest) >= 2 and not re.fullmatch(r"[\d.\sxX]+", rest) else p
    return p


_DESCRIPTOR_TAIL = re.compile(
    r"(?:\s*(?:&|and|/|,)?\s*\b(?:remote terminal units?|controllers?|firmware|software|application|"
    r"applications|web (?:interface|server|ui)|series|family|devices?|products?|platform))+\s*$", re.I)


def trim_descriptors(product: str) -> str:
    """Drop generic trailing descriptors NVD rarely keeps in product tokens
    ('... Remote Terminal Unit & Controller', '... Firmware'). Never empties the name."""
    t = re.sub(r"\(.*?\)", " ", product).strip()
    trimmed = _DESCRIPTOR_TAIL.sub("", t).strip(" -&/,")
    return trimmed if len(trimmed) >= 3 else t
