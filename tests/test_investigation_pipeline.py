import json
import tempfile
import unittest
from pathlib import Path

from investigation_pipeline import analyse_nmap_file, load_inventory


class InvestigationPipelineTests(unittest.TestCase):
    def test_sample_scan_flows_through_parser_inventory_and_engine(self):
        scan = Path(__file__).parents[1] / "sample_scan.xml"
        results = analyse_nmap_file(scan)

        self.assertEqual(len(results), 3)
        statuses = {item["assessment"]["status"] for item in results}
        self.assertEqual(statuses, {"expected"})

    def test_inventory_loader_converts_expected_services_to_set(self):
        inventory = load_inventory()
        self.assertIn("10.10.10.20", inventory)
        self.assertIn("tcp/22", inventory["10.10.10.20"].expected_services)

    def test_unknown_asset_is_preserved_as_insufficient_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            scan = directory / "unknown.xml"
            scan.write_text(
                '<?xml version="1.0"?><nmaprun><host>'
                '<address addr="10.10.10.99"/><ports>'
                '<port protocol="tcp" portid="22"><state state="open"/>'
                '<service name="ssh"/></port></ports></host></nmaprun>',
                encoding="utf-8",
            )
            inventory = directory / "inventory.json"
            inventory.write_text(json.dumps({}), encoding="utf-8")

            result = analyse_nmap_file(scan, inventory)
            self.assertEqual(result[0]["assessment"]["status"], "insufficient_evidence")


if __name__ == "__main__":
    unittest.main()
