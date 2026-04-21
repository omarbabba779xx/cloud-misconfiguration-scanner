import json
import pytest
from pathlib import Path
from scanner.base import Finding, Severity, Category
from reports.renderer import save_json, save_html, print_console
from tests.conftest import make_finding


def _sample_findings():
    return [
        make_finding(severity=Severity.CRITICAL, title="Critical issue"),
        make_finding(severity=Severity.HIGH, title="High issue"),
        make_finding(severity=Severity.MEDIUM, title="Medium issue"),
        make_finding(severity=Severity.LOW, title="Low issue"),
    ]


# ── JSON renderer ─────────────────────────────────────────────────────────────

class TestJSONRenderer:
    def test_json_creates_file(self, tmp_path):
        path = str(tmp_path / "report.json")
        save_json(_sample_findings(), path)
        assert Path(path).exists()

    def test_json_structure(self, tmp_path):
        path = str(tmp_path / "report.json")
        findings = _sample_findings()
        save_json(findings, path)
        data = json.loads(Path(path).read_text())
        assert "scan_time" in data
        assert data["total"] == len(findings)
        assert len(data["findings"]) == len(findings)

    def test_json_finding_fields(self, tmp_path):
        path = str(tmp_path / "report.json")
        save_json([make_finding()], path)
        data = json.loads(Path(path).read_text())
        f = data["findings"][0]
        assert f["provider"] == "aws"
        assert f["severity"] == "HIGH"
        assert f["title"] == "Test finding"
        assert "recommendation" in f

    def test_json_empty_findings(self, tmp_path):
        path = str(tmp_path / "empty.json")
        save_json([], path)
        data = json.loads(Path(path).read_text())
        assert data["total"] == 0
        assert data["findings"] == []

    def test_json_all_severities_present(self, tmp_path):
        path = str(tmp_path / "all.json")
        save_json(_sample_findings(), path)
        data = json.loads(Path(path).read_text())
        severities = {f["severity"] for f in data["findings"]}
        assert severities == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


# ── HTML renderer ─────────────────────────────────────────────────────────────

class TestHTMLRenderer:
    def test_html_creates_file(self, tmp_path):
        path = str(tmp_path / "report.html")
        save_html(_sample_findings(), path)
        assert Path(path).exists()

    def test_html_contains_findings(self, tmp_path):
        path = str(tmp_path / "report.html")
        save_html([make_finding(title="Unique Finding Title XYZ")], path)
        html = Path(path).read_text()
        assert "Unique Finding Title XYZ" in html

    def test_html_contains_severity_counts(self, tmp_path):
        path = str(tmp_path / "report.html")
        save_html(_sample_findings(), path)
        html = Path(path).read_text()
        assert "CRITICAL" in html
        assert "HIGH" in html
        assert "MEDIUM" in html
        assert "LOW" in html

    def test_html_recommendation_present(self, tmp_path):
        path = str(tmp_path / "report.html")
        save_html([make_finding(recommendation="Do this specific thing now")], path)
        html = Path(path).read_text()
        assert "Do this specific thing now" in html

    def test_html_empty_findings(self, tmp_path):
        path = str(tmp_path / "empty.html")
        save_html([], path)
        html = Path(path).read_text()
        assert "0" in html  # total count


# ── Console renderer (smoke test) ─────────────────────────────────────────────

class TestConsoleRenderer:
    def test_print_console_no_exception(self, capsys):
        print_console(_sample_findings())

    def test_print_console_empty_no_exception(self, capsys):
        print_console([])
        captured = capsys.readouterr()
        assert "No misconfigurations" in captured.out

    def test_print_console_sorted_by_severity(self):
        from reports.renderer import _SEVERITY_ORDER
        findings = [
            make_finding(severity=Severity.LOW, title="Low item"),
            make_finding(severity=Severity.CRITICAL, title="Critical item"),
        ]
        # Verify the sort key used by print_console is correct
        sorted_findings = sorted(findings, key=lambda f: _SEVERITY_ORDER[f.severity])
        assert sorted_findings[0].severity == Severity.CRITICAL
        assert sorted_findings[1].severity == Severity.LOW


# ── Finding.to_dict ───────────────────────────────────────────────────────────

class TestFindingToDict:
    def test_to_dict_includes_all_fields(self):
        f = make_finding()
        d = f.to_dict()
        for key in ("provider", "category", "severity", "resource_type",
                    "resource_id", "title", "description", "recommendation"):
            assert key in d

    def test_to_dict_severity_is_string(self):
        f = make_finding(severity=Severity.CRITICAL)
        assert f.to_dict()["severity"] == "CRITICAL"

    def test_to_dict_category_is_string(self):
        f = make_finding(category=Category.NETWORK)
        assert f.to_dict()["category"] == "Network Exposure"
