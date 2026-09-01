import json
import tempfile
import unittest
from pathlib import Path

from investigation_pipeline import InventoryError, analyse_nmap_file, load_inventory
from nmap_parser import NmapParseError, parse_nmap_xml


ROOT = Path(__file__).parents[1]


class InvestigationPipelineTests(unittest.TestCase):
    def test_sample_scan_flows_through_parser_inventory_and_engine(self):
        scan = ROOT / "sample_scan.xml"
        results = analyse_nmap_file(scan)

        self.assertEqual(len(results), 3)
        statuses = {item["assessment"]["status"] for item in results}
        self.assertEqual(statuses, {"expected"})

    def test_closed_port_is_not_an_exposure_observation(self):
        parsed = parse_nmap_xml(ROOT / "sample_scan.xml")
        ports = {item["port"] for item in parsed}
        self.assertNotIn(8080, ports)

    def test_inventory_loader_converts_expected_services_to_lowercase_set(self):
        inventory = load_inventory()
        self.assertIn("10.10.10.20", inventory)
        self.assertIn("tcp/22", inventory["10.10.10.20"].expected_services)
        self.assertIsInstance(inventory["10.10.10.20"].expected_services, frozenset)

    def test_case_data_references_known_inventory_assets(self):
        cases = json.loads((ROOT / "data" / "cases.json").read_text(encoding="utf-8"))
        inventory = load_inventory()
        for case_id, case in cases.items():
            self.assertIn(case["ip"], inventory, msg=f"{case_id} references an unknown inventory IP")
            self.assertEqual(case["owner"], inventory[case["ip"]].owner, msg=case_id)
            self.assertEqual(case["role"], inventory[case["ip"]].role, msg=case_id)
            self.assertEqual(case["criticality"].lower(), inventory[case["ip"]].criticality.lower(), msg=case_id)

    def test_unknown_asset_is_preserved_as_insufficient_evidence(self):
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


if __name__ == "__main__":
    unittest.main()
