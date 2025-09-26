import matplotlib.pyplot as plt
from nmap_parser import parse_nmap_xml

def visualize_ports(scan_file):
    results = parse_nmap_xml(scan_file)

    host_ports = {}
    for entry in results:
        ip = entry['address']
        host_ports.setdefault(ip, []).append(entry)

    for ip, entries in host_ports.items():
        labels = []
        heights = []

        for entry in entries:
            label = f"{entry['port']} ({entry['service']})"
            labels.append(label)
            heights.append(1)

        plt.figure(figsize=(12, 5))
        plt.bar(labels, heights)
        plt.title(f"Open Ports and Services for {ip}")
        plt.xlabel("Port (Service)")
        plt.ylabel("Open")
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()

        filename = f"open_ports_{ip.replace('.', '_')}.png"
        plt.savefig(filename)
        print(f"Saved chart as {filename}")

if __name__ == "__main__":
    visualize_ports("sample_scan.xml")

