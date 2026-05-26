"""Tests for parser."""

import json
import tempfile
from pathlib import Path

import pytest

from parser import parse_sonar_report, load_rule_kb


SAMPLE_REPORT = {
    "issues": [
        {
            "key": "key1",
            "rule": "java:S2259",
            "severity": "CRITICAL",
            "component": "proj:src/main/java/Foo.java",
            "line": 10,
            "message": "NPE risk",
            "status": "OPEN",
            "effort": "5min",
        },
        {
            "key": "key2",
            "rule": "java:S2068",
            "severity": "BLOCKER",
            "component": "proj:src/main/java/Bar.java",
            "line": 20,
            "message": "Hardcoded cred",
            "status": "OPEN",
            "effort": "30min",
        },
        {
            "key": "key3",
            "rule": "java:S106",
            "severity": "MAJOR",
            "component": "proj:src/main/java/Baz.java",
            "line": 30,
            "message": "Use logger",
            "status": "WONTFIX",  # Should be skipped
            "effort": "2min",
        },
        {
            "key": "key4",
            "rule": "java:S1192",
            "severity": "MINOR",
            "component": "proj:src/main/java/Qux.java",
            "line": 5,
            "message": "Dup string",
            "status": "FALSE_POSITIVE",  # Should be skipped
            "effort": "2min",
        },
    ]
}


def _write_report(data: dict) -> str:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as f:
        json.dump(data, f)
        return f.name


class TestParseSonarReport:
    def test_filters_wontfix_and_false_positive(self):
        path = _write_report(SAMPLE_REPORT)
        issues = parse_sonar_report(path)
        statuses = {i["status"] for i in issues}
        assert "WONTFIX" not in statuses
        assert "FALSE_POSITIVE" not in statuses

    def test_sorted_by_severity(self):
        path = _write_report(SAMPLE_REPORT)
        issues = parse_sonar_report(path)
        assert len(issues) == 2
        assert issues[0]["severity"] == "BLOCKER"
        assert issues[1]["severity"] == "CRITICAL"

    def test_fields_present(self):
        path = _write_report(SAMPLE_REPORT)
        issues = parse_sonar_report(path)
        for issue in issues:
            for field in ("key", "rule_key", "severity", "component", "line", "message", "status"):
                assert field in issue

    def test_missing_issues_key_raises(self):
        path = _write_report({"total": 0})
        with pytest.raises(ValueError, match="missing 'issues'"):
            parse_sonar_report(path)

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            parse_sonar_report("/nonexistent/path/report.json")

    def test_empty_issues(self):
        path = _write_report({"issues": []})
        assert parse_sonar_report(path) == []


class TestLoadRuleKb:
    def test_loads_default_kb(self):
        kb = load_rule_kb()
        assert "java:S2259" in kb
        assert "java:S2068" in kb

    def test_kb_entry_has_required_fields(self):
        kb = load_rule_kb()
        for rule_key, entry in kb.items():
            assert "name" in entry, f"Missing 'name' for {rule_key}"
            assert "fix_strategy" in entry, f"Missing 'fix_strategy' for {rule_key}"

    def test_missing_kb_returns_empty(self):
        kb = load_rule_kb("/nonexistent/kb.json")
        assert kb == {}
