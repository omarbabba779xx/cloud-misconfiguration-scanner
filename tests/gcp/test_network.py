import pytest
from unittest.mock import MagicMock, patch
from scanner.gcp.network import GCPNetworkScanner
from scanner.base import Severity
from tests.conftest import assert_finding, no_finding

PROJECT = "test-project"


def _allowed(protocol, ports):
    a = MagicMock()
    a.I_p_protocol = protocol
    a.ports = ports
    return a


def _rule(name, src_ranges, allowed_list, disabled=False):
    r = MagicMock()
    r.name = name
    r.direction = "INGRESS"
    r.disabled = disabled
    r.source_ranges = src_ranges
    r.allowed = allowed_list
    r.self_link = f"projects/{PROJECT}/global/firewalls/{name}"
    return r


def _make_scanner(rules, networks=None):
    with patch("scanner.gcp.network.compute_v1.FirewallsClient") as fc_cls, \
         patch("scanner.gcp.network.compute_v1.NetworksClient") as nc_cls:
        fc = MagicMock()
        fc.list.return_value = rules
        fc_cls.return_value = fc

        nc = MagicMock()
        nc.list.return_value = networks or []
        nc_cls.return_value = nc

        scanner = GCPNetworkScanner.__new__(GCPNetworkScanner)
        scanner.project = PROJECT
        scanner.fw_client = fc
        scanner._nc = nc
        return scanner, fc, nc


# ── Firewall rules ────────────────────────────────────────────────────────────

class TestGCPFirewall:
    def test_ssh_open_to_internet_is_critical(self):
        rule = _rule("allow-ssh", ["0.0.0.0/0"], [_allowed("tcp", ["22"])])
        scanner, fw, nc = _make_scanner([rule])
        with patch("scanner.gcp.network.compute_v1.NetworksClient") as nc_cls:
            nc_cls.return_value.list.return_value = []
            findings = scanner._check_firewall_rules()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="SSH")

    def test_rdp_open_to_internet_is_critical(self):
        rule = _rule("allow-rdp", ["0.0.0.0/0"], [_allowed("tcp", ["3389"])])
        scanner, fw, nc = _make_scanner([rule])
        with patch("scanner.gcp.network.compute_v1.NetworksClient"):
            findings = scanner._check_firewall_rules()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="RDP")

    def test_mysql_open_is_high(self):
        rule = _rule("allow-mysql", ["0.0.0.0/0"], [_allowed("tcp", ["3306"])])
        scanner, fw, nc = _make_scanner([rule])
        findings = scanner._check_firewall_rules()
        assert_finding(findings, severity=Severity.HIGH, title_contains="MySQL")

    def test_all_protocol_is_critical(self):
        rule = _rule("allow-all", ["0.0.0.0/0"], [_allowed("all", [])])
        scanner, fw, nc = _make_scanner([rule])
        findings = scanner._check_firewall_rules()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="all inbound traffic")

    def test_private_source_no_finding(self):
        rule = _rule("corp-ssh", ["10.0.0.0/8"], [_allowed("tcp", ["22"])])
        scanner, fw, nc = _make_scanner([rule])
        findings = scanner._check_firewall_rules()
        no_finding(findings, title_contains="SSH")

    def test_disabled_rule_no_finding(self):
        rule = _rule("disabled-ssh", ["0.0.0.0/0"], [_allowed("tcp", ["22"])], disabled=True)
        scanner, fw, nc = _make_scanner([rule])
        findings = scanner._check_firewall_rules()
        no_finding(findings, title_contains="SSH")

    def test_port_range_containing_ssh_is_critical(self):
        rule = _rule("wide-range", ["0.0.0.0/0"], [_allowed("tcp", ["0-65535"])])
        scanner, fw, nc = _make_scanner([rule])
        findings = scanner._check_firewall_rules()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="SSH")

    def test_http_no_critical(self):
        rule = _rule("allow-http", ["0.0.0.0/0"], [_allowed("tcp", ["80"])])
        scanner, fw, nc = _make_scanner([rule])
        findings = scanner._check_firewall_rules()
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert not critical


# ── Default network ───────────────────────────────────────────────────────────

class TestDefaultNetwork:
    def test_default_network_is_medium(self):
        net = MagicMock()
        net.name = "default"
        net.self_link = f"projects/{PROJECT}/global/networks/default"
        scanner, fw, nc = _make_scanner([])
        with patch("scanner.gcp.network.compute_v1.NetworksClient") as nc_cls:
            nc_cls.return_value.list.return_value = [net]
            findings = scanner._check_default_network()
        assert_finding(findings, severity=Severity.MEDIUM, title_contains="default")

    def test_custom_network_no_finding(self):
        net = MagicMock()
        net.name = "production-vpc"
        scanner, fw, nc = _make_scanner([])
        with patch("scanner.gcp.network.compute_v1.NetworksClient") as nc_cls:
            nc_cls.return_value.list.return_value = [net]
            findings = scanner._check_default_network()
        no_finding(findings, title_contains="default")


# ── Port range helper ─────────────────────────────────────────────────────────

class TestGCPPortInRange:
    def test_exact_match(self):
        assert GCPNetworkScanner._port_in_range(22, "22")

    def test_range_match(self):
        assert GCPNetworkScanner._port_in_range(3306, "3000-4000")

    def test_no_match(self):
        assert not GCPNetworkScanner._port_in_range(22, "80-443")

    def test_invalid(self):
        assert not GCPNetworkScanner._port_in_range(22, "abc")
