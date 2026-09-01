import unittest

from network_exposure import AssetContext, ServiceObservation, assess_service


class NetworkExposureTests(unittest.TestCase):
    def setUp(self):
        self.asset = AssetContext(
            owner="Web Team",
            role="Web server",
            criticality="high",
            authorised=True,
            expected_services=frozenset({"tcp/80", "tcp/443", "tcp/22"}),
        )

    def test_expected_service_is_not_marked_as_malicious(self):
        result = assess_service(ServiceObservation("10.10.10.20", 443, "tcp", "https"), self.asset)
        self.assertEqual(result["status"], "expected")
        self.assertEqual(result["confidence"], "high")
        self.assertFalse(result["evidence_gaps"])

    def test_service_baseline_comparison_is_case_insensitive(self):
        asset = AssetContext("Web Team", "Web server", "high", True, frozenset({"TCP/443"}))
        result = assess_service(ServiceObservation("10.10.10.20", 443, "tcp", "https"), asset)
        self.assertEqual(result["status"], "expected")

    def test_unexpected_service_requires_investigation(self):
        result = assess_service(ServiceObservation("10.10.10.20", 8080, "tcp", "http-proxy"), self.asset)
        self.assertEqual(result["status"], "investigate")
        self.assertEqual(result["confidence"], "medium")
        self.assertTrue(result["evidence_gaps"])
        self.assertIn("service owner", result["evidence_gaps"])
        self.assertTrue(result["recommended_action"])

    def test_unknown_asset_is_insufficient_evidence(self):
        result = assess_service(ServiceObservation("10.10.10.50", 22, "tcp", "ssh"), None)
        self.assertEqual(result["status"], "insufficient_evidence")
        self.assertEqual(result["confidence"], "low")
        self.assertIn("asset owner", result["evidence_gaps"])

    def test_unauthorised_asset_requires_investigation(self):
        asset = AssetContext("Unknown", "Unknown", "unknown", False, frozenset())
        result = assess_service(ServiceObservation("10.10.10.50", 22, "tcp", "ssh"), asset)
        self.assertEqual(result["status"], "investigate")
        self.assertEqual(result["confidence"], "medium")

    def test_invalid_observation_ip_is_rejected(self):
        with self.assertRaises(ValueError):
            ServiceObservation("not-an-ip", 22, "tcp", "ssh")

    def test_invalid_observation_port_is_rejected(self):
        with self.assertRaises(ValueError):
            ServiceObservation("10.10.10.20", 70000, "tcp", "ssh")

    def test_invalid_observation_protocol_is_rejected(self):
        with self.assertRaises(ValueError):
            ServiceObservation("10.10.10.20", 22, "icmp", "ssh")

    def test_invalid_observation_service_is_rejected(self):
        with self.assertRaises(ValueError):
            ServiceObservation("10.10.10.20", 22, "tcp", "")

    def test_invalid_asset_expected_services_are_rejected(self):
        with self.assertRaises(ValueError):
            AssetContext("Web Team", "Web server", "high", True, frozenset({""}))


if __name__ == "__main__":
    unittest.main()
