import tempfile
import unittest
from pathlib import Path

from nmap_parser import NmapParseError, parse_nmap_xml


SAMPLE = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" />
    <address addr="10.10.10.20" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" />
        <service name="ssh" product="OpenSSH" version="9.6" method="probed" conf="10" />
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed" reason="reset" />
        <service name="http" />
      </port>
    </ports>
  </host>
</nmaprun>
"""


class NmapParserTests(unittest.TestCase):
    def test_parses_open_service_context(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scan.xml"
            path.write_text(SAMPLE, encoding="utf-8")
            results = parse_nmap_xml(path)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["address"], "10.10.10.20")
        self.assertEqual(results[0]["port"], 22)
        self.assertEqual(results[0]["service"], "ssh")
        self.assertEqual(results[0]["product"], "OpenSSH")
        self.assertEqual(results[0]["version"], "9.6")
        self.assertEqual(results[0]["service_confidence"], 10)

    def test_rejects_non_nmap_xml(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wrong.xml"
            path.write_text("<root />", encoding="utf-8")
            with self.assertRaises(NmapParseError):
                parse_nmap_xml(path)

    def test_rejects_invalid_host_address(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad-ip.xml"
            path.write_text(
                '<nmaprun><host><address addr="not-an-ip" addrtype="ipv4"/></host></nmaprun>',
                encoding="utf-8",
            )
            with self.assertRaises(NmapParseError):
                parse_nmap_xml(path)

    def test_rejects_invalid_protocol(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad-protocol.xml"
            path.write_text(
                '<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/><ports>'
                '<port protocol="icmp" portid="22"><state state="open"/></port>'
                '</ports></host></nmaprun>',
                encoding="utf-8",
            )
            with self.assertRaises(NmapParseError):
                parse_nmap_xml(path)

    def test_rejects_invalid_service_confidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad-confidence.xml"
            path.write_text(
                '<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/><ports>'
                '<port protocol="tcp" portid="22"><state state="open"/>'
                '<service name="ssh" conf="11"/></port></ports></host></nmaprun>',
                encoding="utf-8",
            )
            with self.assertRaises(NmapParseError):
                parse_nmap_xml(path)

    def test_missing_service_name_becomes_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unknown-service.xml"
            path.write_text(
                '<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/><ports>'
                '<port protocol="tcp" portid="22"><state state="open"/>'
                '<service name="   "/></port></ports></host></nmaprun>',
                encoding="utf-8",
            )
            results = parse_nmap_xml(path)
            self.assertEqual(results[0]["service"], "unknown")


if __name__ == "__main__":
    unittest.main()
