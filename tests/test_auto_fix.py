"""
Tests for the parts of the bot that can be checked without touching GitHub.

The network-facing code is thin on purpose. Everything that makes a decision
about which version to pin lives in these functions, so these are the tests
that matter.

Run with:  pytest tests/
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "bot"))

from auto_fix import (  # noqa: E402
    apply_fixes,
    build_fix_map,
    parse_package_name,
    parse_pinned_version,
    version_key,
)


class TestParsePackageName:
    def test_handles_every_separator(self):
        assert parse_package_name("requests==2.32.0") == "requests"
        assert parse_package_name("PyGithub>=1.55") == "PyGithub"
        assert parse_package_name("urllib3<=1.26.5") == "urllib3"
        assert parse_package_name("flask~=3.0.0") == "flask"
        assert parse_package_name("click!=8.0.0") == "click"

    def test_bare_package_with_no_pin(self):
        assert parse_package_name("flask") == "flask"

    def test_ignores_comments_blanks_and_flags(self):
        assert parse_package_name("# a comment") is None
        assert parse_package_name("") is None
        assert parse_package_name("   ") is None
        assert parse_package_name("-r other-requirements.txt") is None

    def test_strips_trailing_comment(self):
        assert parse_package_name("requests==2.32.0  # pinned on purpose") == "requests"


class TestParsePinnedVersion:
    def test_returns_version_only_for_exact_pins(self):
        assert parse_pinned_version("requests==2.32.0") == "2.32.0"
        assert parse_pinned_version("PyGithub>=1.55") is None
        assert parse_pinned_version("flask") is None


class TestVersionKey:
    def test_orders_normal_releases(self):
        assert version_key("2.8.0") > version_key("1.26.5")
        assert version_key("1.26.18") > version_key("1.26.5")
        assert version_key("2.10.1") > version_key("2.10")

    def test_release_beats_its_own_release_candidate(self):
        assert version_key("2.0.0") > version_key("2.0.0rc1")
        assert version_key("2.0.0rc2") > version_key("2.0.0rc1")

    def test_double_digit_segments_compare_numerically(self):
        # The reason this is not a plain string comparison.
        assert version_key("1.26.5") > version_key("1.9.0")


class TestBuildFixMap:
    def test_takes_the_highest_fix_not_the_last_one_seen(self):
        """
        A package with several CVEs has several FixedVersions. Only the highest
        closes all of them. An earlier version of this code assigned on every
        iteration, so the answer depended on the order Trivy happened to return
        the findings in.
        """
        findings = [
            {"PkgName": "urllib3", "FixedVersion": "2.8.0"},
            {"PkgName": "urllib3", "FixedVersion": "1.26.18"},
            {"PkgName": "urllib3", "FixedVersion": "1.26.5"},
        ]
        assert build_fix_map(findings) == {"urllib3": "2.8.0"}

    def test_order_does_not_change_the_answer(self):
        findings = [
            {"PkgName": "urllib3", "FixedVersion": "1.26.5"},
            {"PkgName": "urllib3", "FixedVersion": "2.8.0"},
        ]
        assert build_fix_map(findings) == {"urllib3": "2.8.0"}

    def test_handles_comma_separated_fixed_versions(self):
        findings = [{"PkgName": "flask", "FixedVersion": "2.3.2, 3.0.1"}]
        assert build_fix_map(findings) == {"flask": "3.0.1"}

    def test_skips_findings_with_no_fix_available(self):
        findings = [
            {"PkgName": "lonely", "FixedVersion": ""},
            {"PkgName": "nameless", "FixedVersion": "1.0.0"},
        ]
        assert build_fix_map(findings) == {"nameless": "1.0.0"}


class TestApplyFixes:
    def test_rewrites_only_the_matching_lines(self):
        content = "PyGithub>=1.55\nPyYAML==5.3.1\nflask==3.0.0\n"
        new_text, changes = apply_fixes(content, {"PyYAML": "5.4"})
        assert new_text == "PyGithub>=1.55\nPyYAML==5.4\nflask==3.0.0\n"
        assert len(changes) == 1
        assert changes[0]["name"] == "PyYAML"

    def test_reports_nothing_when_already_at_the_fixed_version(self):
        content = "PyYAML==5.4\n"
        new_text, changes = apply_fixes(content, {"PyYAML": "5.4"})
        assert new_text == content
        assert changes == []

    def test_flags_a_major_version_change(self):
        content = "urllib3==1.25.8\n"
        _, changes = apply_fixes(content, {"urllib3": "2.8.0"})
        assert changes[0]["major_bump"] is True

    def test_does_not_flag_a_minor_bump(self):
        content = "PyYAML==5.3.1\n"
        _, changes = apply_fixes(content, {"PyYAML": "5.4"})
        assert changes[0]["major_bump"] is False

    def test_leaves_comments_and_blank_lines_alone(self):
        content = "# security pins\n\nPyYAML==5.3.1\n"
        new_text, _ = apply_fixes(content, {"PyYAML": "5.4"})
        assert new_text == "# security pins\n\nPyYAML==5.4\n"

    def test_preserves_a_missing_trailing_newline(self):
        content = "PyYAML==5.3.1"
        new_text, _ = apply_fixes(content, {"PyYAML": "5.4"})
        assert new_text == "PyYAML==5.4"
