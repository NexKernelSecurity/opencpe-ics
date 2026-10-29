# Contributing to OpenCPE-ICS

The most valuable contribution needs no code: **reviewing a CVE the tool was not
sure about.** Each one you confirm becomes a CPE that every scanner using this
feed can match, and your name stays on the record.

## Review a CVE (about 15 minutes)

1. **Pick one.** Open an issue with the *Claim a CVE for review* template so two
   people don't work on the same CVE. Candidates are in [`data/review/`](data/review/);
   [`reports/enrichment-summary.csv`](reports/enrichment-summary.csv) lists them all
   (`outcome = review`).

2. **Read the tool's guess.** Open `data/review/<year>/CVE-….json`. The
   `_annotation.mappings` block says which CPE it proposed and why; the
   `cve.configurations` block holds the proposed CPEs and version ranges.

3. **Check it against two sources.**
   * **The vendor's advisory.** Find it from the CVE page
     (`https://www.cve.org/CVERecord?id=CVE-…`) or the CISA ICS advisory. Confirm the
     exact product names and affected versions.
   * **The NVD CPE dictionary.** Search
     <https://nvd.nist.gov/products/cpe/search> for the vendor and product.
     If NVD already has a CPE for this product, **use its exact spelling**. Invent
     a new name only when nothing exists, following NVD's style: lower case,
     `_` between words, `o:` + `_firmware` for device firmware, `a:` for software.

4. **Write the reviewed record** at `data/reviewed/<year>/CVE-….json`. Start from
   the file in `data/review/`, correct what is wrong, and set the annotation:

   ```json
   "_annotation": {
     "cve_id": "CVE-2026-12345",
     "reviewed_by": "@your-github-name",
     "review_sources": [
       "https://www.cisa.gov/news-events/ics-advisories/icsa-26-…",
       "https://nvd.nist.gov/products/cpe/search/results?keyword=…"
     ],
     "review_notes": "Vendor lists models X and Y; NVD already uses vendor token 'acme'."
   }
   ```

   Rules for `cpeMatch` entries:
   * a range uses `*` as the CPE version plus `versionStartIncluding` /
     `versionEndExcluding` (or the `…Excluding` / `…Including` pairs);
   * a single affected version goes in the CPE itself, with no range keys;
   * list every affected product; leave out products the vendor says are not affected.

5. **Check it locally** (optional; CI runs the same check on your PR):

   ```bash
   python -m opencpe_ics.validate data/reviewed
   ```

6. **Open a pull request** with only your new file. A maintainer checks the
   sources and merges. From the next daily refresh, your record replaces the
   machine output in `data/feed/`, and the refresh never overwrites it.

### What reviewers check

* Every CPE matches what the vendor says is affected, no more and no less.
* Existing NVD spellings were reused where they exist.
* Version ranges match the vendor's advisory.
* `review_sources` actually support the change.

## Report a wrong CPE in the feed

Open an issue with the *Wrong CPE in the feed* template, naming the CVE, what is
wrong, and a link to the vendor's advisory. These are fixed first, because
scanners already use the feed.

## Code contributions

```bash
pip install -e ".[dev]"
pytest -q
```

Accuracy changes must come with before/after numbers from
`opencpe-ics evaluate` (see the README). A change that raises recall but lowers
the precision of the feed will not be merged.

## For instructors

Reviewing CVEs works well as a graded exercise: it teaches students to read
vendor advisories, understand CPE and version ranges, and defend each claim with
a source. Each merged PR is a public, citable contribution. Open an issue if you
would like a batch of CVEs reserved for a class.
