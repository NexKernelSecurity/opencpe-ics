# OpenCPE-ICS

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23750373.svg)](https://doi.org/10.5281/zenodo.23750373)
[![Tests](https://github.com/NexKernelSecurity/opencpe-ics/actions/workflows/tests.yml/badge.svg)](https://github.com/NexKernelSecurity/opencpe-ics/actions/workflows/tests.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**Open, evidence-backed CPE data for industrial (ICS/OT) vulnerabilities that NVD no longer enriches.**

A vulnerability scanner can only report a CVE on your asset if the CVE carries a
**CPE** — the machine-readable "make, model, version" identifier. Since
April 15, 2026, NIST enriches only a priority subset of CVEs. Industrial and
embedded products are mostly outside that subset, so many of their CVEs are
published with no CPE at all, and scanners such as OpenVAS, Wazuh or Grype
silently skip them.

OpenCPE-ICS fills that gap in the open: it converts the vendor's own
`affected` data into NVD-style CPE configurations, attaches a **confidence
score and an evidence trail** to every mapping, and publishes the result in
the same format as [anchore/nvd-data-overrides](https://github.com/anchore/nvd-data-overrides),
so existing tooling can consume it directly.

Built and maintained by **NEXKERNEL**.

---

## The gap, measured (snapshot 2026-10-28)

All CISA ICS advisories published **2026-04-28 → 2026-10-28** (275 advisories, 1,611 unique CVEs),
checked against every freely available CPE source:

| Source | CVEs with a CPE |
|---|---|
| NVD | 1,013 (62.9%) |
| Anchore nvd-data-overrides | 119 (7.4%) — only 57 of them filled an NVD gap |
| CVE record (CNA + CISA ADP) | < 4% |
| **Any free source** | **1,080 (67.0%)** |
| **No CPE anywhere** | **531 (33.0%)** |

* Excluding Siemens (1,099 CVEs, mostly well covered), **72.5%** of ICS CVEs have no CPE anywhere.
* It is not just lag: among non-Siemens CVEs older than 60 days, **61.9%** still have none.
* Of 329 CVEs NIST marked *Deferred*, 278 have no CPE in any free source.
* 527 of the 531 gap CVEs **do** contain structured vendor/product/version data from the vendor — the raw
  material exists; only the translation into CPE is missing. That translation is what this project does.
* VulnCheck's enriched NVD++ index returned **HTTP 402 (Payment Required)** for all 531 gap CVEs on a
  community account, so its coverage could not be checked and is not freely available.

Per-CVE data: [`reports/ics-gap-2026-04-28_2026-10-28.csv`](reports/ics-gap-2026-04-28_2026-10-28.csv).

## Accuracy

Measured honestly with a **temporal split**: aliases were learned only from NVD records published
*before* 2026-04-28, every test CVE was excluded from training, and predictions were scored against the
CPEs NVD analysts later wrote for the 1,013 ICS CVEs that did get enriched.

Precision of each emitted vendor:product mapping, by confidence level:

| Level | All test CVEs | Vendor-own ICS CVEs* | Where it goes |
|---|---|---|---|
| **high** | 890 mappings — **99.8%** correct | 91 — **97.8%** | feed |
| **medium** | 129 — 92.2% | 100 — 94.0% | feed |
| **low** | 114 — 28.1% | 85 — 25.9% | human review only |
| **feed overall** | 1,019 — **98.8%** | 191 — **95.8%** | |

\* CVEs where the vendor describes its own product (138 CVEs) — the population the gap is made of.
The rest of the test set is third-party components (mostly Linux kernel) listed in Siemens advisories.

* **Recall:** for CVEs mapped at high confidence we find 78% of the products NVD lists; overall 64%.
* **Version ranges** agree with NVD's for **64.9%** of correctly matched vendor-own products
  (73% at high, 92% at medium). Most disagreements are NVD's own conventions (merging stable branches,
  rewriting `<= X` as `< X.next`, adding branches the vendor did not list); we follow the vendor's data.

Full per-CVE results: [`reports/evaluation.csv`](reports/evaluation.csv).

## What is published

```
data/feed/<year>/CVE-*.json       high + medium confidence, plus human-reviewed records -> for scanners
data/review/<year>/CVE-*.json     low confidence            -> needs a human (PRs welcome)
data/reviewed/<year>/CVE-*.json   human-confirmed records   -> never overwritten by the refresh
reports/enrichment-summary.csv    one line per gap CVE
```

Current run over the 531 gap CVEs: **164 in the feed** (133 high, 31 medium), **362 for review**,
5 unresolvable (no usable vendor data or not yet in NVD). The feed includes 68 Linux kernel CVEs that
Siemens lists for its products and NVD has deferred.

Each record keeps NVD's shape and adds an `_annotation` explaining every decision:

```json
"mappings": [{
  "cna_vendor": "Hitachi Energy",
  "cna_product": "RTU500 series CMU firmware",
  "cpe": "o:hitachienergy:rtu540_firmware",
  "confidence": 0.636, "level": "medium", "method": "alias",
  "evidence": [
    "vendor 'Hitachi Energy' was written as 'hitachienergy' by NVD in 73 of 75 past CVEs (e.g. CVE-2021-35528, ...)",
    "product 'RTU500 series CMU firmware' was written as 'rtu540_firmware' by NVD in 3 past CVE(s) (e.g. CVE-2022-2081, ...)"
  ]
}]
```

## How it works

1. **Corpus** — stream the full NVD mirror ([fkie-cad/nvd-json-data-feeds](https://github.com/fkie-cad/nvd-json-data-feeds),
   ~415k CVEs) into a compact file holding the CNA `affected` data and NVD's CPEs.
2. **Learn** — record how NVD analysts historically translated each vendor/product string into CPE tokens
   (11k vendor and 68k product aliases), keeping example CVE IDs as evidence.
3. **Gap** — collect CVEs from CISA's ICS CSAF advisories and keep those with no CPE in NVD,
   the CVE record, or Anchore's overrides.
4. **Match** — for each gap CVE, in order of trust:
   CNA-supplied CPE (checked against NVD's vocabulary; e.g. a CNA writing `palo_alto_networks` is corrected
   to NVD's `paloaltonetworks`) → learned alias (recent spellings weighted up, since vendors rename) →
   existing NVD vendor/product (fuzzy, scored) → new token derived from the vendor's text (always *low*). Version data is converted from CVE 5.x `versions`, including Siemens-style
   `V3.1`, free-text forms (`17.00 and prior`), compound ranges, and per-branch fixes (Linux kernel style).
   Mappings whose versions cannot be derived are capped at *low* to avoid flagging every version.
5. **Publish** — high/medium to `data/feed`, low to `data/review`, refreshed daily by GitHub Actions.

## Use it

```bash
pip install -e .
opencpe-ics corpus   CVE-all.json.xz corpus.jsonl
opencpe-ics learn    corpus.jsonl aliases.json
opencpe-ics gap      --csaf CSAF/csaf_files/OT/white --anchore nvd-data-overrides --corpus corpus.jsonl --out gap.csv
opencpe-ics enrich   --corpus corpus.jsonl --aliases aliases.json --cves gap.csv --out out/
opencpe-ics evaluate corpus.jsonl gap.csv --cutoff 2026-04-28
```

`enrich` also accepts a plain list of CVE IDs, so it works for any CVE, not only ICS ones.
See [`.github/workflows/refresh.yml`](.github/workflows/refresh.yml) for the full daily pipeline.

## Limitations (read before relying on it)

* **Agreement with NVD is the yardstick.** Where NVD and the vendor disagree, we follow the vendor.
* **New products have no precedent.** A product NVD has never seen gets a derived name and stays in review;
  its token may differ from what NVD eventually picks.
* **Recall is partial.** We find about two thirds of the products NVD lists; multi-product advisories are the hardest.
* **"All versions" is sometimes correct.** When a vendor states every version is affected with no fix
  (common in Siemens advisories), the CPE carries no version bound. When the vendor gave *no* usable version
  data, the mapping is capped at *low* instead, because it would flag every version.
* **Hardware CPEs** (`h:` running-on configurations) are not generated yet; firmware/application CPEs are.
* **Evaluation set is skewed** toward Siemens and third-party components bundled in Siemens products;
  vendor-own numbers rest on a smaller sample (138 CVEs, 191 feed-level mappings).
* No `matchCriteriaId` is emitted (it is NVD-internal).

## Contributing

The most valuable contribution is reviewing a CVE from `data/review/`: check the tool's guess against the
vendor's advisory and the NVD CPE dictionary, then add the corrected record under `data/reviewed/`.
It takes about 15 minutes and needs no code. The step-by-step guide is in [CONTRIBUTING.md](CONTRIBUTING.md).

Found a wrong CPE in the feed? Open a *Wrong CPE in the feed* issue with a link to the vendor's advisory.

## Citing

If you use the tool or the dataset in research, please cite it using [`CITATION.cff`](CITATION.cff)
(GitHub's *Cite this repository* button gives APA and BibTeX), or cite the archived release:
[doi:10.5281/zenodo.23750373](https://doi.org/10.5281/zenodo.23750373).

## License

Code: Apache-2.0. Data is derived from NVD (U.S. Government work) and the CVE List (CVE Terms of Use) and is
redistributed under the same terms.
