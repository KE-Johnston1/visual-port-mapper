import json
import tempfile
import unittest
from pathlib import Path

from investigation_pipeline import CaseDataError, InventoryError, analyse_nmap_file, load_cases, load_inventory
from nmap_parser import NmapParseError, parse_nmap_xml
from network_exposure import AssetContext


ROOT = Path(__file__).parents[1]


class InvestigationPipelineTests(unittest.TestCase):
    def test_sample_scan_flows_through_parser_inventory_and_engine(self):
        results = analyse_nmap_file(ROOT / "sample_scan.xml")
        self.assertEqual(len(results), 3)
        statuses = {item["assessment"]["status"] for item in results}
        self.assertEqual(statuses, {"expected"})

    def test_closed_port_is_not_an_exposure_observation(self):
        parsed = parse_nmap_xml(ROOT / "sample_scan.xml")
        self.assertNotIn(8080, {item["port"] for item in parsed})

    def test_inventory_loader_normalises_expected_services(self):
        inventory = load_inventory()
        self.assertIn("tcp/22", inventory["10.10.10.20"].expected_services)
        self.assertIsInstance(inventory["10.10.10.20"].expected_services, frozenset)

    def test_case_data_matches_inventory(self):
        cases = load_cases()
        inventory = load_inventory()
        self.assertEqual(set(cases), {"NET-001", "NET-002"})
        for case_id, case in cases.items():
            context = inventory[case["ip"]]
            self.assertEqual(case["owner"], context.owner, case_id)
            self.assertEqual(case["role"], context.role, case_id)
            self.assertEqual(case["criticality"].lower(), context.criticality.lower(), case_id)
            self.assertTrue(case["verification_checks"], case_id)

    def test_case_expected_services_use_protocol_qualified_keys(self):
        cases = load_cases()
        for case_id, case in cases.items():
            for service_key in case["expected_services"]:
                self.assertRegex(service_key, r"^(tcp|udp)/[1-9][0-9]{0,4}$", case_id)
                self.assertIn(service_key, {f"{s['protocol'].lower()}/{s['port']}" for s in case["discovered_services"]})

    def test_console_uses_service_presence_matrix_language(self):
        console = (ROOT / "docs" / "investigation-console.html").read_text(encoding="utf-8")
        self.assertIn("Service-presence matrix", console)
        self.assertNotIn("Exposure heatmap</h2>", console)
        self.assertIn("serviceKey(s)", console)

    def test_asset_context_rejects_invalid_expected_service_keys(self):
        for expected in (frozenset({"ssh/22"}), frozenset({"tcp/0"}), frozenset({"tcp/65536"}), frozenset({"icmp/7"}), frozenset({"TCP/22"})):
            with self.subTest(expected=expected):
                with self.assertRaises(ValueError):
                    AssetContext("Team", "Server", "High", True, expected)

    def test_asset_context_rejects_empty_context_fields(self):
        with self.assertRaises(ValueError):
            AssetContext("", "Server", "High", True, frozenset())
        with self.assertRaises(ValueError):
            AssetContext("Team", "", "High", True, frozenset())
        with self.assertRaises(ValueError):
            AssetContext("Team", "Server", "", True, frozenset())

    def test_unknown_asset_is_insufficient_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            scan = directory / "unknown.xml"
            scan.write_text(
                '<?xml version="1.0"?><nmaprun><host>'
                '<address addr="10.10.10.99" addrtype="ipv4"/><ports>'
                '<port protocol="tcp" portid="22"><state state="open"/>'
                '<service name="ssh"/></port></ports></host></nmaprun>',
                encoding="utf-8",
            )
            inventory = directory / "inventory.json"
            inventory.write_text(json.dumps({}), encoding="utf-8")
            result = analyse_nmap_file(scan, inventory)
            self.assertEqual(result[0]["assessment"]["status"], "insufficient_evidence")

    def test_malformed_scan_raises_domain_error(self):
        with tempfile.TemporaryDirectory() as directory:
            scan = Path(directory) / "broken.xml"
            scan.write_text("<nmaprun><host>", encoding="utf-8")
            with self.assertRaises(NmapParseError):
                parse_nmap_xml(scan)

    def test_invalid_inventory_raises_domain_error(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory) / "inventory.json"
            inventory.write_text(json.dumps({"10.0.0.1": {"owner": "Team"}}), encoding="utf-8")
            with self.assertRaises(InventoryError):
                load_inventory(inventory)

    def test_invalid_inventory_ip_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory) / "inventory.json"
            inventory.write_text(json.dumps({"not-an-ip": {
                "owner": "Team", "role": "Server", "criticality": "low",
                "authorised": True, "expected_services": []
            }}), encoding="utf-8")
            with self.assertRaises(InventoryError):
                load_inventory(inventory)

    def test_invalid_expected_service_format_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory) / "inventory.json"
            inventory.write_text(json.dumps({"10.0.0.1": {
                "owner": "Team", "role": "Server", "criticality": "low",
                "authorised": True, "expected_services": ["ssh/99999"]
            }}), encoding="utf-8")
            with self.assertRaises(InventoryError):
                load_inventory(inventory)

    def test_unsupported_expected_service_protocol_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory) / "inventory.json"
            inventory.write_text(json.dumps({"10.0.0.1": {
                "owner": "Team", "role": "Server", "criticality": "low",
                "authorised": True, "expected_services": ["icmp/7"]
            }}), encoding="utf-8")
            with self.assertRaises(InventoryError):
                load_inventory(inventory)

    def test_case_loader_rejects_unknown_inventory_asset(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cases.json"
            cases = load_cases()
            cases["NET-BAD"] = dict(cases["NET-001"], ip="10.10.10.99")
            path.write_text(json.dumps(cases), encoding="utf-8")
            with self.assertRaises(CaseDataError):
                load_cases(path)

    def test_case_loader_rejects_invalid_discovered_port(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cases.json"
            cases = load_cases()
            cases["NET-BAD"] = dict(cases["NET-001"], discovered_services=[{"port": 70000, "protocol": "tcp", "service": "SSH"}])
            path.write_text(json.dumps(cases), encoding="utf-8")
            with self.assertRaises(CaseDataError):
                load_cases(path)

    def test_case_loader_rejects_numeric_expected_services(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cases.json"
            cases = load_cases()
            cases["NET-BAD"] = dict(cases["NET-002"], expected_services=[22, 80, 443])
            path.write_text(json.dumps(cases), encoding="utf-8")
            with self.assertRaises(CaseDataError):
                load_cases(path)

    def test_case_loader_rejects_expected_service_protocol_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cases.json"
            cases = load_cases()
            cases["NET-BAD"] = dict(cases["NET-002"], expected_services=["udp/80"])
            path.write_text(json.dumps(cases), encoding="utf-8")
            with self.assertRaises(CaseDataError):
                load_cases(path)

    def test_case_loader_rejects_missing_required_field(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cases.json"
            cases = load_cases()
            bad = dict(cases["NET-001"])
            bad.pop("verification_checks")
            cases["NET-BAD"] = bad
            path.write_text(json.dumps(cases), encoding="utf-8")
            with self.assertRaises(CaseDataError):
                load_cases(path)

    def test_case_loader_rejects_empty_verification_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cases.json"
            cases = load_cases()
            cases["NET-BAD"] = dict(cases["NET-001"], verification_checks=[])
            path.write_text(json.dumps(cases), encoding="utf-8")
            with self.assertRaises(CaseDataError):
                load_cases(path)


if __name__ == "__main__":
    unittest.main()
