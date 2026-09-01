"""End-to-end evidence pipeline for the Network Exposure & Investigation Lab.

The pipeline connects Nmap XML evidence to the asset inventory and the
context-aware assessment engine. It performs no network activity itself.
"""

import ipaddress
import json
from pathlib import Path
from typing import Any

from nmap_parser import parse_nmap_xml
from network_exposure import AssetContext, ServiceObservation, assess_observations


ROOT = Path(__file__).parent
DEFAULT_INVENTORY = ROOT / "data" / "asset_inventory.json"
DEFAULT_CASES = ROOT / "data" / "cases.json"


class InventoryError(ValueError):
    """Raised when an asset inventory cannot be loaded safely."""


class CaseDataError(ValueError):
    """Raised when investigation case data is invalid or inconsistent."""


def _validate_service_key(service: str, *, source: str) -> str:
    """Validate and normalise a protocol/port service key."""
    parts = service.strip().lower().split("/", 1)
    if len(parts) != 2 or not parts[0] or not parts[1].isdigit():
        raise InventoryError(f"{source} contains invalid service {service!r}; expected protocol/port.")
    if not 1 <= int(parts[1]) <= 65535:
        raise InventoryError(f"{source} contains invalid port in {service!r}.")
    return f"{parts[0]}/{int(parts[1])}"


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
        try:
            ipaddress.ip_address(str(ip))
        except ValueError as exc:
            raise InventoryError(f"Inventory key {ip!r} is not a valid IP address.") from exc

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
        normalised_expected = {
            _validate_service_key(item, source=f"Inventory record for {ip!r}")
            for item in expected
        }

        inventory[str(ip)] = AssetContext(
            owner=str(value["owner"]),
            role=str(value["role"]),
            criticality=str(value["criticality"]),
            authorised=value["authorised"],
            expected_services=frozenset(normalised_expected),
        )

    return inventory


def load_cases(path: str | Path = DEFAULT_CASES, inventory: dict[str, AssetContext] | None = None) -> dict[str, dict[str, Any]]:
    """Load and validate browser investigation cases against the inventory."""
    cases_path = Path(path)
    try:
        raw: Any = json.loads(cases_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CaseDataError(f"Unable to load investigation cases: {cases_path}") from exc

    if not isinstance(raw, dict) or not raw:
        raise CaseDataError("Investigation cases must contain a non-empty JSON object keyed by case ID.")

    inventory = inventory if inventory is not None else load_inventory()
    required = {"title", "asset", "ip", "owner", "role", "criticality", "discovered_services", "expected_services", "known", "evidence_gaps", "timeline", "assessment_guidance"}

    for case_id, case in raw.items():
        if not isinstance(case_id, str) or not case_id.strip():
            raise CaseDataError("Case IDs must be non-empty strings.")
        if not isinstance(case, dict):
            raise CaseDataError(f"Case {case_id!r} must be an object.")
        missing = required - case.keys()
        if missing:
            raise CaseDataError(f"Case {case_id!r} is missing: {', '.join(sorted(missing))}.")

        ip = str(case["ip"])
        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise CaseDataError(f"Case {case_id!r} contains invalid IP {ip!r}.") from exc
        if ip not in inventory:
            raise CaseDataError(f"Case {case_id!r} references inventory IP {ip!r} that does not exist.")

        context = inventory[ip]
        if str(case["owner"]) != context.owner or str(case["role"]) != context.role:
            raise CaseDataError(f"Case {case_id!r} owner/role does not match the inventory for {ip}.")
        if str(case["criticality"]).lower() != context.criticality.lower():
            raise CaseDataError(f"Case {case_id!r} criticality does not match the inventory for {ip}.")

        discovered = case["discovered_services"]
        if not isinstance(discovered, list):
            raise CaseDataError(f"Case {case_id!r} discovered_services must be a list.")
        discovered_keys: set[str] = set()
        for service in discovered:
            if not isinstance(service, dict) or not {"port", "protocol", "service"}.issubset(service):
                raise CaseDataError(f"Case {case_id!r} contains an invalid discovered service record.")
            port = service["port"]
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                raise CaseDataError(f"Case {case_id!r} contains invalid port {port!r}.")
            protocol = str(service["protocol"]).strip().lower()
            if not protocol:
                raise CaseDataError(f"Case {case_id!r} contains an empty service protocol.")
            discovered_keys.add(f"{protocol}/{port}")

        expected = case["expected_services"]
        if not isinstance(expected, list) or not all(isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535 for port in expected):
            raise CaseDataError(f"Case {case_id!r} expected_services must contain valid port numbers.")
        expected_keys = {f"tcp/{port}" for port in expected}
        if not expected_keys.issubset(discovered_keys):
            raise CaseDataError(f"Case {case_id!r} lists expected ports that are not present in discovered_services.")

        for field in ("known", "evidence_gaps"):
            if not isinstance(case[field], list) or not all(isinstance(item, str) and item.strip() for item in case[field]):
                raise CaseDataError(f"Case {case_id!r} field {field!r} must contain non-empty strings.")
        if not isinstance(case["timeline"], list) or not all(isinstance(item, dict) and {"time", "event"}.issubset(item) for item in case["timeline"]):
            raise CaseDataError(f"Case {case_id!r} timeline must contain time/event records.")
        if not isinstance(case["assessment_guidance"], dict):
            raise CaseDataError(f"Case {case_id!r} assessment_guidance must be an object.")

    return raw


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
    inventory = load_inventory()
    load_cases(inventory=inventory)
    scan = ROOT / "sample_scan.xml"
    for item in analyse_nmap_file(scan, DEFAULT_INVENTORY):
        observation = item["observation"]
        assessment = item["assessment"]
        print(
            f"{observation.ip} {observation.protocol}/{observation.port} "
            f"{observation.service}: {assessment['status']} "
            f"({assessment['confidence']})"
        )
