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


if __name__ == "__main__":
    unittest.main()
