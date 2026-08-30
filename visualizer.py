"""Create a simple visual summary from parsed Nmap observations."""

from pathlib import Path

import matplotlib.pyplot as plt

from nmap_parser import parse_nmap_xml


def visualize_ports(scan_file: str | Path, output_dir: str | Path = "outputs") -> list[Path]:
    """Save one service-exposure chart per discovered host.

    This is a presentation utility only. It consumes parsed scan data and does
    not perform scanning or make security decisions.
    """
    results = parse_nmap_xml(scan_file)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    generated: list[Path] = []

    host_ports: dict[str, list[dict]] = {}
    for entry in results:
        host_ports.setdefault(entry["address"], []).append(entry)

    for ip, entries in host_ports.items():
        entries.sort(key=lambda item: (item["protocol"], item["port"]))
        labels = [f"{entry['port']}/{entry['protocol']}\n{entry['service']}" for entry in entries]
        heights = [1] * len(entries)

        figure, axis = plt.subplots(figsize=(12, 5))
        axis.bar(labels, heights)
        axis.set_title(f"Discovered Open Services — {ip}")
        axis.set_xlabel("Port / Protocol / Service")
        axis.set_ylabel("Observed")
        figure.tight_layout()

        filename = output_path / f"open_services_{ip.replace(':', '_').replace('.', '_')}.png"
        figure.savefig(filename)
        plt.close(figure)
        generated.append(filename)

    return generated


if __name__ == "__main__":
    for chart in visualize_ports("sample_scan.xml"):
        print(f"Saved chart: {chart}")
