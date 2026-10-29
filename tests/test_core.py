from collections import Counter

from opencpe_ics.aliases import AliasTable
from opencpe_ics.cpe import build_cpe, cpe_name, parse_cpe, versions_to_bounds
from opencpe_ics.matcher import Matcher, guess_part, strip_vendor_prefix, trim_descriptors
from opencpe_ics.normalize import norm_vendor, split_affected
from opencpe_ics.versioncmp import ranges_agree


def test_parse_and_build_roundtrip():
    s = build_cpe("o", "schneider-electric", "easylogic_t150_firmware", "1.2")
    p = parse_cpe(s)
    assert p["part"] == "o" and p["vendor"] == "schneider-electric" and p["version"] == "1.2"


def test_escape_special_chars():
    s = build_cpe("a", "rockwellautomation", "1756-enbt/a_firmware")
    assert "1756-enbt\\/a_firmware" in s
    assert parse_cpe(s) is not None


def test_cpe_name_drops_trademarks_and_parentheses():
    assert cpe_name("EcoStruxure™ Panel Server") == "ecostruxure_panel_server"
    assert cpe_name("EasyLogic T150 (formerly Saitel DR)") == "easylogic_t150"


def test_norm_vendor_strips_corporate_suffixes():
    assert norm_vendor("Johnson Controls Inc.") == "johnson controls"
    assert norm_vendor("Quanovate Tech Inc. (operating as Mira / Mira Care)") == "quanovate"


def test_versions_siemens_style():
    b = versions_to_bounds([{"version": "0", "lessThan": "V3.1.5", "status": "affected"}])
    assert b == [{"version": "*", "versionEndExcluding": "3.1.5"}]


def test_versions_text_and_compound_forms():
    b = versions_to_bounds([{"version": "V17.00.00 and prior", "status": "affected"}])
    assert b[0]["versionEndIncluding"] == "17.00.00"
    b = versions_to_bounds([{"version": ">= 3.10.0, < 3.17.0", "status": "affected"}])
    assert b[0] == {"version": "*", "versionStartIncluding": "3.10.0", "versionEndExcluding": "3.17.0"}
    b = versions_to_bounds([{"version": "<= 2.0", "status": "affected"}])
    assert b[0]["versionEndIncluding"] == "2.0"


def test_git_only_versions_give_no_bounds():
    assert versions_to_bounds([{"version": "a", "lessThan": "b", "versionType": "git", "status": "affected"}]) == []


def test_versions_skip_unaffected_and_git():
    b = versions_to_bounds([{"version": "abc", "lessThan": "def", "versionType": "git", "status": "affected"},
                            {"version": "2.0", "status": "unaffected"},
                            {"version": "1.4", "status": "affected"}])
    assert b == [{"version": "1.4"}]


def test_ranges_agree_inclusive_vs_exclusive():
    assert ranges_agree([{"_exact": "*", "versionEndIncluding": "17.00.00"}],
                        [{"_exact": "*", "versionEndExcluding": "17.00.01"}])
    assert not ranges_agree([{"_exact": "*", "versionEndExcluding": "3.2"}],
                            [{"_exact": "*", "versionEndExcluding": "3.1"}])


def test_split_affected_prefers_primary_cna():
    aff = [{"vendor": "Linux", "product": "Linux", "source": "cna-a"},
           {"vendor": "Siemens", "product": "S7-1500", "source": "siemens"}]
    prim, other = split_affected(aff, "cna-a")
    assert [a["vendor"] for a in prim] == ["Linux"] and len(other) == 1


def test_guess_part_and_name_helpers():
    assert guess_part("Studio 5000 Logix Designer", None) == "a"
    assert guess_part("Reyrolle 7SR5", None) == "o"
    assert strip_vendor_prefix("Camunda 7", "camunda") == "Camunda 7"
    assert strip_vendor_prefix("Siemens SIMATIC S7-1500", "siemens") == "SIMATIC S7-1500"
    assert trim_descriptors("EasyLogic T150 Remote Terminal Unit & Controller") == "EasyLogic T150"


def _toy_aliases():
    t = AliasTable()
    rec = {"id": "CVE-2025-0001", "source": "psirt@acme",
           "affected": [{"vendor": "ACME Corp.", "product": "PowerLink 500", "source": "psirt@acme"}],
           "cpes": [{"part": "o", "vendor": "acme", "product": "powerlink_500_firmware", "version": "*"}]}
    for i in range(3):
        rec["id"] = f"CVE-2025-000{i}"
        t.learn(rec)
    return t


def test_alias_learning_and_high_confidence_match():
    m = Matcher(_toy_aliases())
    maps = m.map_cve([{"vendor": "ACME Corp.", "product": "PowerLink 500",
                       "versions": [{"version": "0", "lessThan": "V2.1", "status": "affected"}]}])
    assert len(maps) == 1
    x = maps[0]
    assert (x.part, x.vendor, x.product) == ("o", "acme", "powerlink_500_firmware")
    assert x.level == "high" and x.method == "alias"
    assert x.matches[0]["versionEndExcluding"] == "2.1"
    assert any("CVE-2025-000" in e for e in x.evidence)


def test_unknown_product_is_low_confidence():
    m = Matcher(_toy_aliases())
    maps = m.map_cve([{"vendor": "ACME", "product": "CloudView Portal"}])
    assert maps and maps[0].level == "low" and maps[0].method == "derived"


def test_cna_supplied_cpe_is_used_verbatim():
    m = Matcher(AliasTable())
    maps = m.map_cve([{"vendor": "X", "product": "Y", "cpes": ["cpe:2.3:a:x:y:*:*:*:*:*:*:*:*"]}])
    assert maps[0].method == "cna-supplied" and maps[0].vendor == "x"


def test_alias_table_save_load(tmp_path):
    t = _toy_aliases()
    p = tmp_path / "a.json"
    t.save(p)
    t2 = AliasTable.load(p)
    assert t2.vendor["acme"] == Counter({"acme": 3})
    assert t2.product[("acme", "powerlink 500")][("o", "powerlink_500_firmware")] == 3


def test_branch_fix_ranges_like_nvd():
    v = [{"version": "2.6.34", "status": "affected"},
         {"version": "0", "lessThan": "2.6.34", "status": "unaffected"},
         {"version": "5.15.190", "lessThanOrEqual": "5.15.*", "status": "unaffected"},
         {"version": "6.1.149", "lessThanOrEqual": "6.1.*", "status": "unaffected"},
         {"version": "6.17", "lessThanOrEqual": "*", "status": "unaffected"}]
    b = versions_to_bounds(v)
    assert b[0] == {"version": "*", "versionStartIncluding": "2.6.34", "versionEndExcluding": "5.15.190"}
    assert b[1] == {"version": "*", "versionStartIncluding": "5.16", "versionEndExcluding": "6.1.149"}
    assert b[2] == {"version": "*", "versionStartIncluding": "6.2", "versionEndExcluding": "6.17"}


def test_cna_supplied_cpe_vendor_is_corrected_to_nvd_spelling():
    t = AliasTable()
    rec = {"source": "psirt@pan", "affected": [{"vendor": "Palo Alto Networks", "product": "PAN-OS", "source": "psirt@pan"}],
           "cpes": [{"part": "o", "vendor": "paloaltonetworks", "product": "pan-os", "version": "*"}]}
    for i in range(5):
        rec["id"], rec["published"] = f"CVE-2024-000{i}", "2024-01-01"
        t.learn(rec)
    m = Matcher(t)
    x = m.map_cve([{"vendor": "Palo Alto Networks", "product": "PAN-OS",
                    "cpes": ["cpe:2.3:o:palo_alto_networks:pan-os:*:*:*:*:*:*:*:*"]}])[0]
    assert x.vendor == "paloaltonetworks" and x.method == "cna-supplied, vendor corrected"
    assert x.level == "high"


def test_reviewed_records_replace_machine_output(tmp_path):
    import json
    from opencpe_ics.enrich import enrich
    corpus = tmp_path / "c.jsonl"
    corpus.write_text(json.dumps({"id": "CVE-2026-0001", "published": "2026-05-01", "status": "Deferred",
                                  "source": "x", "affected": [{"vendor": "ACME", "product": "Widget", "source": "x"}],
                                  "cpes": []}) + "\n")
    rev = tmp_path / "reviewed" / "2026"
    rev.mkdir(parents=True)
    rec = {"_annotation": {"cve_id": "CVE-2026-0001", "reviewed_by": "student"},
           "cve": {"configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [
               {"vulnerable": True, "criteria": "cpe:2.3:o:acme:widget_firmware:*:*:*:*:*:*:*:*"}]}]}]}}
    (rev / "CVE-2026-0001.json").write_text(json.dumps(rec))
    out = tmp_path / "out"
    out.mkdir()
    s = enrich(corpus, Matcher(AliasTable()), ["CVE-2026-0001"], out, reviewed_dir=tmp_path / "reviewed")
    assert s[0]["level"] == "reviewed" and s[0]["cpes"] == "o:acme:widget_firmware"
    assert json.loads((out / "feed" / "2026" / "CVE-2026-0001.json").read_text())["_annotation"]["reviewed_by"] == "student"
    assert not (out / "review" / "2026" / "CVE-2026-0001.json").exists()


def test_validate_reviewed_record(tmp_path):
    import json
    from opencpe_ics.validate import check_file
    d = tmp_path / "2026"
    d.mkdir()
    good = {"_annotation": {"cve_id": "CVE-2026-0001", "reviewed_by": "@student",
                            "review_sources": ["https://www.cisa.gov/news-events/ics-advisories/icsa-26-001-01"]},
            "cve": {"configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [
                {"vulnerable": True, "criteria": "cpe:2.3:o:acme:widget_firmware:*:*:*:*:*:*:*:*",
                 "versionEndExcluding": "2.1"}]}]}]}}
    f = d / "CVE-2026-0001.json"
    f.write_text(json.dumps(good))
    assert check_file(f) == []
    good["_annotation"].pop("reviewed_by")
    good["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0]["criteria"] = "cpe:2.3:o:acme:widget"
    f.write_text(json.dumps(good))
    errs = check_file(f)
    assert any("reviewed_by" in e for e in errs) and any("13 fields" in e for e in errs)
