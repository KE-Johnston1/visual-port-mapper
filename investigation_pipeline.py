"""End-to-end evidence pipeline for the Network Exposure & Investigation Lab.

The pipeline connects Nmap observations, asset context and synthetic network
telemetry. It performs no network activity itself.
"""

import ipaddress
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from nmap_parser import parse_nmap_xml
from network_exposure import AssetContext, ServiceObservation, assess_observations

ROOT = Path(__file__).parent
DEFAULT_INVENTORY = ROOT / "data" / "asset_inventory.json"
DEFAULT_CASES = ROOT / "data" / "cases.json"
DEFAULT_TELEMETRY = ROOT / "data" / "network_telemetry.json"


class InventoryError(ValueError):
    """Raised when an asset inventory cannot be loaded safely."""


class CaseDataError(ValueError):
    """Raised when investigation case data is invalid or inconsistent."""


class TelemetryError(ValueError):
    """Raised when synthetic network telemetry is invalid or inconsistent."""


def _validate_service_key(service: str, *, source: str) -> str:
    """Validate and normalise a protocol/port service key."""
    if not isinstance(service, str):
        raise InventoryError(f"{source} contains a non-string service {service!r}.")
    parts = service.strip().lower().split("/", 1)
    if len(parts) != 2 or parts[0] not in {"tcp", "udp"} or not parts[1].isdigit():
        raise InventoryError(f"{source} contains invalid service {service!r}; expected tcp/port or udp/port.")
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
            raise InventoryError(f"Inventory record for {ip!r} is missing: {', '.join(sorted(missing))}.")
        if not isinstance(value["authorised"], bool):
            raise InventoryError(f"Inventory record for {ip!r} must use a boolean for 'authorised'.")
        expected = value.get("expected_services", [])
        if not isinstance(expected, list) or not all(isinstance(item, str) for item in expected):
            raise InventoryError(f"Inventory record for {ip!r} must contain a list of service strings.")
        normalised_expected = {_validate_service_key(item, source=f"Inventory record for {ip!r}") for item in expected}
        inventory[str(ip)] = AssetContext(
            owner=str(value["owner"]), role=str(value["role"]), criticality=str(value["criticality"]),
            authorised=value["authorised"], expected_services=frozenset(normalised_expected)
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
    required = {"title", "asset", "ip", "owner", "role", "criticality", "discovered_services", "expected_services", "known", "evidence_gaps", "verification_checks", "timeline", "assessment_guidance"}
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
            if protocol not in {"tcp", "udp"}:
                raise CaseDataError(f"Case {case_id!r} contains unsupported protocol {protocol!r}.")
            if not isinstance(service["service"], str) or not service["service"].strip():
                raise CaseDataError(f"Case {case_id!r} contains an empty service name.")
            discovered_keys.add(f"{protocol}/{port}")
        expected = case["expected_services"]
        if not isinstance(expected, list) or not all(isinstance(item, str) for item in expected):
            raise CaseDataError(f"Case {case_id!r} expected_services must contain protocol/port service keys.")
        expected_keys = {_validate_service_key(item, source=f"Case {case_id!r}") for item in expected}
        if not expected_keys.issubset(discovered_keys):
            raise CaseDataError(f"Case {case_id!r} lists expected services that are not present in discovered_services.")
        for field in ("known", "evidence_gaps", "verification_checks"):
            if not isinstance(case[field], list) or not all(isinstance(item, str) and item.strip() for item in case[field]):
                raise CaseDataError(f"Case {case_id!r} field {field!r} must contain non-empty strings.")
        if not case["verification_checks"]:
            raise CaseDataError(f"Case {case_id!r} must contain at least one verification check.")
        if not isinstance(case["timeline"], list) or not all(isinstance(item, dict) and {"time", "event"}.issubset(item) for item in case["timeline"]):
            raise CaseDataError(f"Case {case_id!r} timeline must contain time/event records.")
        if not isinstance(case["assessment_guidance"], dict):
            raise CaseDataError(f"Case {case_id!r} assessment_guidance must be an object.")
    return raw


def load_network_telemetry(path: str | Path = DEFAULT_TELEMETRY) -> dict[str, dict[str, list[dict[str, Any]]]]:
    """Load and validate synthetic firewall, IDS and IPS evidence."""
    telemetry_path = Path(path)
    try:
        raw: Any = json.loads(telemetry_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TelemetryError(f"Unable to load network telemetry: {telemetry_path}") from exc
    if not isinstance(raw, dict) or not raw:
        raise TelemetryError("Network telemetry must contain a non-empty object keyed by case ID.")

    required_common = {"timestamp", "source_ip", "destination_ip", "destination_port", "protocol", "action"}
    for case_id, sources in raw.items():
        if not isinstance(case_id, str) or not case_id.strip() or not isinstance(sources, dict):
            raise TelemetryError(f"Telemetry case {case_id!r} must be a non-empty ID with an object of evidence sources.")
        for source in ("firewall", "ids", "ips"):
            events = sources.get(source, [])
            if not isinstance(events, list):
                raise TelemetryError(f"Telemetry case {case_id!r} source {source!r} must be a list.")
            for event in events:
                if not isinstance(event, dict) or not required_common.issubset(event):
                    raise TelemetryError(f"Telemetry case {case_id!r} contains an incomplete {source} event.")
                try:
                    datetime.fromisoformat(str(event["timestamp"]))
                    ipaddress.ip_address(str(event["source_ip"]))
                    ipaddress.ip_address(str(event["destination_ip"]))
                except ValueError as exc:
                    raise TelemetryError(f"Telemetry case {case_id!r} contains invalid timestamp or IP data.") from exc
                port = event["destination_port"]
                if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                    raise TelemetryError(f"Telemetry case {case_id!r} contains invalid destination port {port!r}.")
                if str(event["protocol"]).strip().lower() not in {"tcp", "udp"}:
                    raise TelemetryError(f"Telemetry case {case_id!r} contains unsupported protocol.")
                if not isinstance(event["action"], str) or not event["action"].strip():
                    raise TelemetryError(f"Telemetry case {case_id!r} contains an empty action.")
                if source in {"ids", "ips"} and ("signature" not in event or "severity" not in event):
                    raise TelemetryError(f"Telemetry case {case_id!r} {source} events require signature and severity context.")
    return raw


def analyse_nmap_file(scan_file: str | Path, inventory_file: str | Path = DEFAULT_INVENTORY) -> list[dict]:
    """Parse an Nmap XML file and assess each observed open service."""
    parsed = parse_nmap_xml(scan_file)
    observations = [ServiceObservation(ip=item["address"], port=item["port"], protocol=item["protocol"], service=item["service"]) for item in parsed]
    return assess_observations(observations, load_inventory(inventory_file))


if __name__ == "__main__":
    inventory = load_inventory()
    load_cases(inventory=inventory)
    load_network_telemetry()
    for item in analyse_nmap_file(ROOT / "sample_scan.xml", DEFAULT_INVENTORY):
        observation = item["observation"]
        assessment = item["assessment"]
        print(f"{observation.ip} {observation.protocol}/{observation.port} {observation.service}: {assessment['status']} ({assessment['confidence']})")
