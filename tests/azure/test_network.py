import pytest
from unittest.mock import MagicMock
from scanner.azure.network import AzureNetworkScanner
from scanner.base import Severity
from tests.conftest import assert_finding, no_finding


def _rule(name, port_range, src="*", access="Allow", direction="Inbound"):
    r = MagicMock()
    r.name = name
    r.direction = direction
    r.access = access
    r.source_address_prefix = src
    r.destination_port_range = port_range
    r.destination_port_ranges = []
    return r


def _nsg(name, rules, location="eastus"):
    nsg = MagicMock()
    nsg.name = name
    nsg.id = f"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/{name}"
    nsg.location = location
    nsg.security_rules = rules
    return nsg


def _make_scanner(nsgs, nics=None):
    scanner = AzureNetworkScanner.__new__(AzureNetworkScanner)
    client = MagicMock()
    client.network_security_groups.list_all.return_value = nsgs
    client.network_interfaces.list_all.return_value = nics or []
    scanner.client = client
    return scanner


# ── NSG rules ─────────────────────────────────────────────────────────────────

class TestNSGRules:
    def test_ssh_open_to_internet_is_critical(self):
        nsg = _nsg("test-nsg", [_rule("allow-ssh", "22")])
        findings = _make_scanner([nsg]).scan()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="SSH")

    def test_rdp_open_to_internet_is_critical(self):
        nsg = _nsg("test-nsg", [_rule("allow-rdp", "3389")])
        findings = _make_scanner([nsg]).scan()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="RDP")

    def test_mysql_open_is_high(self):
        nsg = _nsg("test-nsg", [_rule("allow-mysql", "3306")])
        findings = _make_scanner([nsg]).scan()
        assert_finding(findings, severity=Severity.HIGH, title_contains="MySQL")

    def test_all_ports_wildcard_is_critical(self):
        nsg = _nsg("test-nsg", [_rule("allow-all", "*")])
        findings = _make_scanner([nsg]).scan()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="allows ALL inbound")

    def test_port_range_containing_ssh_is_critical(self):
        nsg = _nsg("test-nsg", [_rule("wide-range", "20-25")])
        findings = _make_scanner([nsg]).scan()
        assert_finding(findings, severity=Severity.CRITICAL, title_contains="SSH")

    def test_deny_rule_no_finding(self):
        nsg = _nsg("test-nsg", [_rule("deny-ssh", "22", access="Deny")])
        findings = _make_scanner([nsg]).scan()
        no_finding(findings, title_contains="SSH")

    def test_egress_rule_ignored(self):
        nsg = _nsg("test-nsg", [_rule("egress-ssh", "22", direction="Outbound")])
        findings = _make_scanner([nsg]).scan()
        no_finding(findings, title_contains="SSH")

    def test_restricted_source_no_finding(self):
        nsg = _nsg("test-nsg", [_rule("corp-ssh", "22", src="10.0.0.0/8")])
        findings = _make_scanner([nsg]).scan()
        no_finding(findings, title_contains="SSH")

    def test_http_open_no_critical_finding(self):
        nsg = _nsg("test-nsg", [_rule("allow-http", "80")])
        findings = _make_scanner([nsg]).scan()
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert not critical


# ── Port range helper ─────────────────────────────────────────────────────────

class TestPortInRange:
    def test_exact_match(self):
        assert AzureNetworkScanner._port_in_range(22, "22")

    def test_range_match(self):
        assert AzureNetworkScanner._port_in_range(22, "0-65535")

    def test_wildcard(self):
        assert AzureNetworkScanner._port_in_range(22, "*")

    def test_no_match(self):
        assert not AzureNetworkScanner._port_in_range(22, "80-443")

    def test_invalid_range(self):
        assert not AzureNetworkScanner._port_in_range(22, "abc-def")
