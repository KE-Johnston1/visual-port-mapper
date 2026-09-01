"""Parse authorised Nmap XML into structured network observations.

The parser is deliberately limited to reading scan output. It does not execute
Nmap or perform network activity.
"""

import ipaddress
from pathlib import Path
from typing import Any

from defusedxml import ElementTree as ET


class NmapParseError(ValueError):
    """Raised when an Nmap XML document cannot be interpreted safely."""


def parse_nmap_xml(file_path: str | Path) -> list[dict[str, Any]]:
    """Return open-service observations from an Nmap XML file.

    Closed and filtered ports are ignored because the investigation model is
    focused on exposed services. Useful service context is preserved when it
    is present in the scan output.
    """
    path = Path(file_path)
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise NmapParseError(f"Unable to parse Nmap XML: {path}") from exc

    if root.tag != "nmaprun":
        raise NmapParseError("Input does not appear to be an Nmap XML document.")

    results: list[dict[str, Any]] = []

    for host in root.findall("host"):
        addresses = host.findall("address")
        address = next(
            (item.get("addr") for item in addresses if item.get("addrtype") in {"ipv4", "ipv6"}),
            None,
        )
        if not address:
            continue
        try:
            ipaddress.ip_address(address)
        except ValueError as exc:
            raise NmapParseError(f"Invalid host address in Nmap XML: {address!r}") from exc

        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            protocol = (port.get("protocol") or "").strip().lower()
            if protocol not in {"tcp", "udp"}:
                raise NmapParseError(f"Invalid protocol for {address}: {protocol!r}")

            port_id = port.get("portid")
            if not port_id or not port_id.isdigit():
                raise NmapParseError(f"Invalid port number for {address}: {port_id!r}")
            port_number = int(port_id)
            if not 1 <= port_number <= 65535:
                raise NmapParseError(f"Invalid port number for {address}: {port_number}")

            service = port.find("service")
            service_name = (service.get("name", "unknown").strip() if service is not None else "unknown") or "unknown"

            observation: dict[str, Any] = {
                "address": address,
                "port": port_number,
                "protocol": protocol,
                "service": service_name,
                "state": "open",
            }

            if service is not None:
                for key in ("product", "version", "extrainfo", "method"):
                    value = service.get(key)
                    if value:
                        observation[key] = value

                confidence = service.get("conf")
                if confidence is not None:
                    if not confidence.isdigit() or not 0 <= int(confidence) <= 10:
                        raise NmapParseError(
                            f"Invalid service confidence for {address}:{port_number}: {confidence!r}"
                        )
                    observation["service_confidence"] = int(confidence)

            results.append(observation)

    return results
