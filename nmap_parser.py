"""Parse authorised Nmap XML into structured network observations.

The parser is deliberately limited to reading scan output. It does not execute
Nmap or perform network activity.
"""

from pathlib import Path
from typing import Any

from defusedxml import ElementTree as ET


class NmapParseError(ValueError):
    """Raised when an Nmap XML document cannot be interpreted safely."""


def parse_nmap_xml(file_path: str | Path) -> list[dict[str, Any]]:
    """Return open-service observations from an Nmap XML file.

    The parser keeps useful Nmap context such as service product/version and
    Nmap's service-confidence value. Closed/filtered ports are ignored because
    the investigation model is focused on exposed services.
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
            addresses[0].get("addr") if addresses else None,
        )
        if not address:
            continue

        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            protocol = (port.get("protocol") or "unknown").lower()
            port_id = port.get("portid")
            if not port_id or not port_id.isdigit():
                continue

            service = port.find("service")
            service_name = service.get("name", "unknown") if service is not None else "unknown"

            observation: dict[str, Any] = {
                "address": address,
                "port": int(port_id),
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
                if confidence and confidence.isdigit():
                    observation["service_confidence"] = int(confidence)

            results.append(observation)

    return results
