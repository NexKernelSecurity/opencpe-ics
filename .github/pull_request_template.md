## What this changes

<!-- For a review: "Reviewed CVE-…, closes #<issue>" -->

## Checklist for reviewed records

- [ ] File is at `data/reviewed/<year>/<CVE>.json`
- [ ] `_annotation` has `cve_id`, `reviewed_by` and `review_sources` (https links)
- [ ] Existing NVD CPE spellings were reused where they exist
- [ ] Products and version ranges match the vendor's advisory
- [ ] `python -m opencpe_ics.validate data/reviewed` passes
