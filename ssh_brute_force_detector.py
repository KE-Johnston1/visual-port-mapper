import matplotlib.pyplot as plt

import re
from collections import defaultdict
THRESHOLD = 3  # You can change this number anytime

# Step 1: Load the log file
log_file = "sample_auth.log"

# Step 2: Create a dictionary to count failed attempts per IP
ip_attempts = defaultdict(int)

# Step 3: Define a regex pattern to match failed SSH login lines
pattern = r"Failed password.*from (\d+\.\d+\.\d+\.\d+)"

# Step 4: Read the log file and count IPs
with open(log_file, "r") as file:
    for line in file:
        match = re.search(pattern, line)
        if match:
            ip = match.group(1)
            ip_attempts[ip] += 1

# Step 5: Print IPs with more than 3 failed attempts
print(f"Suspicious IPs with more than {THRESHOLD} failed login attempts:")
for ip, count in ip_attempts.items():
    if count > THRESHOLD:
        print(f"{ip} - {count} attempts")
with open("suspicious_ips.txt", "w") as output:
    for ip, count in ip_attempts.items():
        if count > THRESHOLD:
            output.write(f"{ip} - {count} attempts\n")
# Step 6: Visualize all IP attempts
ips = list(ip_attempts.keys())
counts = list(ip_attempts.values())

plt.figure(figsize=(8, 4))
plt.bar(ips, counts, color="skyblue")
plt.xlabel("IP Address")
plt.ylabel("Failed Attempts")
plt.title("SSH Login Failures by IP")
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("ssh_attempts_chart.png")
plt.show()
