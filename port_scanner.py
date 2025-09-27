import socket

# Step 1: Load suspicious IPs from file
with open("suspicious_ips.txt", "r") as file:
    ips = [line.strip().split(" - ")[0] for line in file]

# Step 2: Define ports to scan
common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389]


# Step 3: Scan each IP
for ip in ips:
    print(f"\nScanning {ip}...")
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                print(f"Port {port} is OPEN")
            else:
                print(f"Port {port} is CLOSED")
            sock.close()
        except Exception as e:
            print(f"Error scanning {ip}:{port} - {e}")
print("\nScan complete.")
print("Closed ports may indicate firewalls, inactive services, or spoofed IPs.")
print("Open ports could signal exposed services worth investigating further.")

