"""End-to-end evidence pipeline for the Network Exposure & Investigation Lab.

The pipeline connects Nmap XML evidence to the asset inventory and the
context-aware assessment engine. It performs no network activity itself.
"""

import json
from pathlib import Path
from typing import Any

from nmap_parser import parse_nmap_xml
from network_exposure import AssetContext, ServiceObservation, assess_observations


DEFAULT_INVENTORY = Path(__file__).parent / "data" / "asset_inventory.json"


class InventoryError(ValueError):
    """Raised when an asset inventory cannot be loaded safely."""


def load_inventory(path: str | Path = DEFAULT_INVENTORY) -> dict[str, AssetContext]:
    """Load and validate the JSON asset inventory."""
    inventory_path = Path(path)
    try:
        raw: Any = json.loads(inventory_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InventoryError(f"Unable to load asset inventory: {inventory_path}") from exc

    if not isinstance(raw, dict):
        raise InventoryError("Asset inventory must contain a JSON object keyed by IP address.")

    inventory: dict[str, AssetContext] = {}
    required = {"owner", "role", "criticality", "authorised"}

    for ip, value in raw.items():
        if not isinstance(value, dict):
            raise InventoryError(f"Inventory record for {ip!r} must be an object.")
        missing = required - value.keys()
        if missing:
            missing_text = ", ".join(sorted(missing))
            raise InventoryError(f"Inventory record for {ip!r} is missing: {missing_text}.")
        if not isinstance(value["authorised"], bool):
            raise InventoryError(f"Inventory record for {ip!r} must use a boolean for 'authorised'.")

        expected = value.get("expected_services", [])
        if not isinstance(expected, list) or not all(isinstance(item, str) for item in expected):
            raise InventoryError(f"Inventory record for {ip!r} must contain a list of service strings.")

        inventory[str(ip)] = AssetContext(
            owner=str(value["owner"]),
            role=str(value["role"]),
            criticality=str(value["criticality"]),
            authorised=value["authorised"],
            expected_services=frozenset(item.lower() for item in expected),
        )

    return inventory


def analyse_nmap_file(
    scan_file: str | Path, inventory_file: str | Path = DEFAULT_INVENTORY
) -> list[dict]:
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
