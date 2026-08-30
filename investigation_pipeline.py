"""End-to-end evidence pipeline for the Network Exposure & Investigation Lab.

The pipeline connects Nmap XML evidence to the asset inventory and the
context-aware assessment engine. It performs no network activity itself.
"""

import json
from pathlib import Path

from nmap_parser import parse_nmap_xml
from network_exposure import AssetContext, ServiceObservation, assess_observations


DEFAULT_INVENTORY = Path(__file__).parent / "data" / "asset_inventory.json"


def load_inventory(path=DEFAULT_INVENTORY):
    """Load the JSON asset inventory and convert records to AssetContext."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return {
        ip: AssetContext(
            owner=value["owner"],
            role=value["role"],
            criticality=value["criticality"],
            authorised=value["authorised"],
            expected_services=frozenset(value.get("expected_services", [])),
        )
        for ip, value in raw.items()
    }


def analyse_nmap_file(scan_file, inventory_file=DEFAULT_INVENTORY):
    """Parse an Nmap XML file and assess each observed open service."""
    parsed = parse_nmap_xml(scan_file)
    observations = [
        ServiceObservation(
            ip=item["address"],
            port=item["port"],
            protocol=item["protocol"],
            service=item["service"],
        )
        for item in parsed
    ]
    return assess_observations(observations, load_inventory(inventory_file))


if __name__ == "__main__":
    scan = Path(__file__).parent / "sample_scan.xml"
    for item in analyse_nmap_file(scan):
        observation = item["observation"]
        assessment = item["assessment"]
        print(
            f"{observation.ip} {observation.protocol}/{observation.port} "
            f"{observation.service}: {assessment['status']} "
            f"({assessment['confidence']})"
        )
