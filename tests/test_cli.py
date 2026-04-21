import pytest
from click.testing import CliRunner
from unittest.mock import patch, MagicMock
from main import main
from scanner.base import Finding, Severity, Category
from tests.conftest import make_finding


def _patch_run(findings=None):
    """Return a context manager that stubs all three provider runners."""
    findings = findings or []
    return patch("main._parallel", return_value=findings)


# ── Basic invocation ──────────────────────────────────────────────────────────

class TestCLIBasic:
    def test_help_exits_zero(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Cloud misconfiguration scanner" in result.output

    def test_aws_only_no_credentials_error_is_handled(self):
        runner = CliRunner()
        with patch("main._run_aws", side_effect=Exception("No credentials")), \
             patch("main._parallel", return_value=[]):
            result = runner.invoke(main, ["-p", "aws"])
        assert result.exit_code == 0

    def test_azure_without_subscription_prints_error(self):
        runner = CliRunner()
        result = runner.invoke(main, ["-p", "azure"])
        assert "AZURE_SUBSCRIPTION_ID required" in result.output

    def test_gcp_without_project_prints_error(self):
        runner = CliRunner()
        result = runner.invoke(main, ["-p", "gcp"])
        assert "GCP_PROJECT_ID required" in result.output


# ── Severity filtering ────────────────────────────────────────────────────────

class TestSeverityFilter:
    def test_min_severity_high_excludes_medium(self, tmp_path):
        findings = [
            make_finding(severity=Severity.CRITICAL, title="Crit"),
            make_finding(severity=Severity.MEDIUM, title="Med"),
        ]
        runner = CliRunner()
        json_path = str(tmp_path / "out.json")
        with _patch_run(findings):
            result = runner.invoke(
                main,
                ["-p", "aws", "--min-severity", "HIGH",
                 "--output", "json", "--output-file", str(tmp_path / "out")]
            )
        import json
        data = json.loads((tmp_path / "out.json").read_text())
        titles = [f["title"] for f in data["findings"]]
        assert "Crit" in titles
        assert "Med" not in titles

    def test_min_severity_info_includes_all(self, tmp_path):
        findings = [
            make_finding(severity=Severity.INFO, title="Info item"),
            make_finding(severity=Severity.CRITICAL, title="Crit item"),
        ]
        runner = CliRunner()
        with _patch_run(findings):
            result = runner.invoke(
                main,
                ["-p", "aws", "--min-severity", "INFO",
                 "--output", "json", "--output-file", str(tmp_path / "out")]
            )
        import json
        data = json.loads((tmp_path / "out.json").read_text())
        assert data["total"] == 2


# ── --fail-on exit code ───────────────────────────────────────────────────────

class TestFailOn:
    def test_fail_on_critical_exits_1_when_critical_present(self):
        findings = [make_finding(severity=Severity.CRITICAL)]
        runner = CliRunner()
        with _patch_run(findings):
            result = runner.invoke(main, ["-p", "aws", "--fail-on", "CRITICAL"])
        assert result.exit_code == 1

    def test_fail_on_critical_exits_0_when_only_high(self):
        findings = [make_finding(severity=Severity.HIGH)]
        runner = CliRunner()
        with _patch_run(findings):
            result = runner.invoke(main, ["-p", "aws", "--fail-on", "CRITICAL"])
        assert result.exit_code == 0

    def test_fail_on_none_exits_0_always(self):
        findings = [make_finding(severity=Severity.CRITICAL)]
        runner = CliRunner()
        with _patch_run(findings):
            result = runner.invoke(main, ["-p", "aws", "--fail-on", "NONE"])
        assert result.exit_code == 0

    def test_fail_on_high_exits_1_when_critical_present(self):
        findings = [make_finding(severity=Severity.CRITICAL)]
        runner = CliRunner()
        with _patch_run(findings):
            result = runner.invoke(main, ["-p", "aws", "--fail-on", "HIGH"])
        assert result.exit_code == 1


# ── Output formats ────────────────────────────────────────────────────────────

class TestOutputFormats:
    def test_json_output_creates_file(self, tmp_path):
        runner = CliRunner()
        with _patch_run([make_finding()]):
            runner.invoke(
                main,
                ["-p", "aws", "--output", "json",
                 "--output-file", str(tmp_path / "report")]
            )
        assert (tmp_path / "report.json").exists()

    def test_html_output_creates_file(self, tmp_path):
        runner = CliRunner()
        with _patch_run([make_finding()]):
            runner.invoke(
                main,
                ["-p", "aws", "--output", "html",
                 "--output-file", str(tmp_path / "report")]
            )
        assert (tmp_path / "report.html").exists()

    def test_all_output_creates_both_files(self, tmp_path):
        runner = CliRunner()
        with _patch_run([make_finding()]):
            runner.invoke(
                main,
                ["-p", "aws", "--output", "all",
                 "--output-file", str(tmp_path / "report")]
            )
        assert (tmp_path / "report.json").exists()
        assert (tmp_path / "report.html").exists()


# ── Category selection ────────────────────────────────────────────────────────

class TestCategorySelection:
    def test_single_category(self):
        runner = CliRunner()
        with _patch_run([]) as mock_parallel:
            result = runner.invoke(main, ["-p", "aws", "-c", "storage"])
        assert result.exit_code == 0

    def test_multiple_categories(self):
        runner = CliRunner()
        with _patch_run([]):
            result = runner.invoke(main, ["-p", "aws", "-c", "storage", "-c", "network"])
        assert result.exit_code == 0
