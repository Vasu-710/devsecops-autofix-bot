"""Tests for the Trivy output parser.

This script decides what the fixer is even allowed to see. If it drops a
finding or counts one twice, every number downstream is wrong.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "bot"))

from parse_trivy import load_results, split_by_severity  # noqa: E402


def vuln(pkg, vid, severity, fixed="1.0.0"):
    return {
        "PkgName": pkg,
        "VulnerabilityID": vid,
        "Severity": severity,
        "FixedVersion": fixed,
    }


def results(*sections):
    return {"Results": [{"Vulnerabilities": list(s)} for s in sections]}


class TestSplitBySeverity:
    def test_sorts_findings_into_the_two_buckets(self):
        data = results([
            vuln("a", "CVE-1", "HIGH"),
            vuln("b", "CVE-2", "CRITICAL"),
        ])
        out = split_by_severity(data)
        assert [v["VulnerabilityID"] for v in out["HIGH"]] == ["CVE-1"]
        assert [v["VulnerabilityID"] for v in out["CRITICAL"]] == ["CVE-2"]

    def test_ignores_severities_the_bot_does_not_act_on(self):
        data = results([
            vuln("a", "CVE-1", "MEDIUM"),
            vuln("b", "CVE-2", "LOW"),
            vuln("c", "CVE-3", "UNKNOWN"),
        ])
        assert split_by_severity(data) == {"HIGH": [], "CRITICAL": []}

    def test_drops_a_finding_repeated_across_result_sections(self):
        """Trivy lists per section, so one CVE can arrive more than once."""
        data = results(
            [vuln("urllib3", "CVE-1", "HIGH")],
            [vuln("urllib3", "CVE-1", "HIGH")],
        )
        assert len(split_by_severity(data)["HIGH"]) == 1

    def test_keeps_the_same_cve_for_different_packages(self):
        data = results([
            vuln("a", "CVE-1", "HIGH"),
            vuln("b", "CVE-1", "HIGH"),
        ])
        assert len(split_by_severity(data)["HIGH"]) == 2

    def test_keeps_different_cves_for_one_package(self):
        data = results([
            vuln("urllib3", "CVE-1", "HIGH"),
            vuln("urllib3", "CVE-2", "HIGH"),
        ])
        assert len(split_by_severity(data)["HIGH"]) == 2

    def test_the_same_cve_at_two_severities_is_not_merged(self):
        data = results([
            vuln("a", "CVE-1", "HIGH"),
            vuln("a", "CVE-1", "CRITICAL"),
        ])
        out = split_by_severity(data)
        assert len(out["HIGH"]) == 1 and len(out["CRITICAL"]) == 1

    def test_a_clean_scan_gives_empty_buckets_not_a_crash(self):
        assert split_by_severity({"Results": []}) == {"HIGH": [], "CRITICAL": []}

    def test_missing_results_key_is_survivable(self):
        assert split_by_severity({}) == {"HIGH": [], "CRITICAL": []}

    def test_null_results_and_null_vulnerabilities_are_survivable(self):
        # Trivy writes null rather than [] when a target has nothing.
        assert split_by_severity({"Results": None}) == {"HIGH": [], "CRITICAL": []}
        assert split_by_severity({"Results": [{"Vulnerabilities": None}]}) == {
            "HIGH": [], "CRITICAL": []
        }

    def test_the_whole_finding_is_kept_not_just_its_id(self):
        data = results([vuln("urllib3", "CVE-1", "HIGH", fixed="2.8.0")])
        assert split_by_severity(data)["HIGH"][0]["FixedVersion"] == "2.8.0"


class TestLoadResults:
    def test_reads_a_valid_file(self, tmp_path):
        path = tmp_path / "t.json"
        path.write_text(json.dumps({"Results": []}))
        assert load_results(str(path)) == {"Results": []}

    def test_a_missing_file_stops_the_run(self, tmp_path):
        """Silently continuing would report a clean scan that never happened."""
        with pytest.raises(SystemExit) as e:
            load_results(str(tmp_path / "nope.json"))
        assert "does not exist" in str(e.value)

    def test_malformed_json_stops_the_run(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("{not json")
        with pytest.raises(SystemExit) as e:
            load_results(str(path))
        assert "not valid JSON" in str(e.value)


class TestHandoffToTheFixer:
    """The two scripts only talk through one JSON file. Nothing else checks
    that they still agree on its shape."""

    def test_the_parsers_output_feeds_the_fixer_unchanged(self):
        from auto_fix import build_fix_map

        data = results([
            vuln("urllib3", "CVE-1", "HIGH", fixed="1.26.18"),
            vuln("urllib3", "CVE-2", "HIGH", fixed="2.8.0"),
            vuln("PyYAML", "CVE-3", "CRITICAL", fixed="5.4"),
        ])
        buckets = split_by_severity(data)

        # This is exactly what auto_fix.main() does with the parsed file.
        findings = buckets.get("HIGH", []) + buckets.get("CRITICAL", [])
        assert build_fix_map(findings) == {"urllib3": "2.8.0", "PyYAML": "5.4"}

    def test_the_keys_are_the_ones_the_fixer_looks_up(self):
        buckets = split_by_severity({"Results": []})
        assert set(buckets) == {"HIGH", "CRITICAL"}
