import matplotlib.pyplot as plt
from nmap_parser import parse_nmap_xml

def visualize_ports(scan_file):
    results = parse_nmap_xml(scan_file)

    # Group ports by IP address
    host_ports = {}
    for entry in results:
        ip = entry['address']
        port = entry['port']
        host_ports.setdefault(ip, []).append(port)

    for ip, ports in host_ports.items():
        plt.figure(figsize=(10, 4))
        plt.bar(ports, [1]*len(ports))
        plt.title(f"Open Ports for {ip}")
        plt.xlabel("Port Number")
        plt.ylabel("Open")
        plt.tight_layout()
        plt.show()

# Example usage
if __name__ == "__main__":
    visualize_ports("sample_scan.xml")
