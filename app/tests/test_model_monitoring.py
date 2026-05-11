import unittest

from app.services.model_monitoring import ModelMonitoringService
from app.ml.registry import model_registry


class ModelMonitoringServiceTests(unittest.TestCase):
    def test_population_stability_index_is_zero_for_matching_distribution(self):
        service = ModelMonitoringService()
        score = service._population_stability_index([0.2, 0.3, 0.5], [0.2, 0.3, 0.5])
        self.assertLess(score, 0.0001)

    def test_explain_normalizes_geo_distance_alias(self):
        service = ModelMonitoringService()
        features = service._normalize_input_features({"geo_distance": 42, "login_hour": 9})
        self.assertEqual(features["geo_distance_from_last_login"], 42)
        self.assertEqual(features["login_hour"], 9)

    def test_confusion_counts_from_attempt_like_objects(self):
        service = ModelMonitoringService()

        class Attempt:
            def __init__(self, success, risk_score, decision):
                self.success = success
                self.risk_score = risk_score
                self.decision = decision

        counts = service._confusion_counts_from_attempts([
            Attempt(True, 10, "allow"),
            Attempt(True, 80, "require_verification"),
            Attempt(False, 10, "allow"),
            Attempt(False, 90, "block"),
        ])
        self.assertEqual(counts, {"tn": 1, "fp": 1, "fn": 1, "tp": 1})

    def test_registry_keeps_isolation_forest_as_default(self):
        self.assertEqual(model_registry.default_model_key, "isolation_forest")
        self.assertTrue(model_registry.get().available)
        self.assertIn("xgboost", [item["key"] for item in model_registry.list_models()])


if __name__ == "__main__":
    unittest.main()
