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


if __name__ == "__main__":
    unittest.main()
