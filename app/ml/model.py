from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.utils.validation import check_is_fitted
import pandas as pd
import numpy as np
from typing import List, Dict, Any
import joblib
import os

from app.config import settings

FEATURE_COLUMNS = [
    "login_hour",
    "location_lat",
    "location_lon",
    "typing_speed",
    "failed_attempts",
    "ip_risk_score",
    "device_usage_frequency",
    "login_interval_hours",
    "geo_distance_from_last_login",
]

class AnomalyDetectionModel:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.threshold = 0.0
        self.score_min = -1.0
        self.score_max = 1.0
        self.model_path = "app/ml/isolation_forest.joblib"

    def load_model(self):
        if os.path.exists(self.model_path):
            stored = joblib.load(self.model_path)
            if isinstance(stored, dict):
                self.model = stored.get("model")
                self.scaler = stored.get("scaler")
                self.threshold = float(stored.get("threshold", 0.0))
                self.score_min = float(stored.get("score_min", -1.0))
                self.score_max = float(stored.get("score_max", 1.0))
            else:
                # Backward compatibility with older single-object model files.
                self.model = stored
                self.scaler = None
                self.threshold = 0.0
                self.score_min = -1.0
                self.score_max = 1.0
        else:
            self.model = IsolationForest(contamination="auto", random_state=42)
            self.scaler = StandardScaler()
            self.threshold = 0.0
            self.score_min = -1.0
            self.score_max = 1.0

    def save_model(self):
        joblib.dump(
            {
                "model": self.model,
                "scaler": self.scaler,
                "threshold": self.threshold,
                "score_min": self.score_min,
                "score_max": self.score_max,
            },
            self.model_path,
        )

    def _prepare_dataframe(self, data: List[Dict[str, Any]]) -> pd.DataFrame:
        df = pd.DataFrame(data)
        for column in FEATURE_COLUMNS:
            if column not in df:
                df[column] = 0
        df = df[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce").fillna(0.0)
        return df

    def train(self, data: List[Dict[str, Any]]):
        if not data or len(data) < settings.min_training_samples:
            return False

        # Prepare a stable numeric feature matrix before fitting the scaler and model.
        df = self._prepare_dataframe(data)
        self.scaler = StandardScaler()
        scaled_df = self.scaler.fit_transform(df)
        self.model = IsolationForest(contamination="auto", random_state=42)
        self.model.fit(scaled_df)

        decision_scores = self.model.decision_function(scaled_df)
        self.score_min = float(np.min(decision_scores))
        self.score_max = float(np.max(decision_scores))
        percentile_floor = max(0.0, 100.0 - settings.model_threshold_percentile)
        self.threshold = float(np.percentile(decision_scores, percentile_floor))
        self.save_model()
        return True

    def predict_anomaly_score(self, features: Dict[str, Any]) -> Dict[str, Any]:
        if self.model is None:
            self.load_model()

        if self.model is None or self.scaler is None:
            return {
                "raw_score": 0.0,
                "normalized_score": 0.0,
                "is_anomalous": False,
                "top_contributors": [],
            }

        try:
            check_is_fitted(self.scaler)
        except Exception:
            return {
                "raw_score": 0.0,
                "normalized_score": 0.0,
                "is_anomalous": False,
                "top_contributors": [],
            }

        df = self._prepare_dataframe([features])
        scaled_df = self.scaler.transform(df)
        raw_score = float(self.model.decision_function(scaled_df)[0])

        score_range = max(self.score_max - self.score_min, 1e-6)
        normalized_score = (self.score_max - raw_score) / score_range
        normalized_score = max(0.0, min(1.0, normalized_score))

        scaled_values = np.abs(scaled_df[0])
        contributors = sorted(
            [
                {"feature": feature_name, "deviation": float(deviation)}
                for feature_name, deviation in zip(FEATURE_COLUMNS, scaled_values)
            ],
            key=lambda item: item["deviation"],
            reverse=True,
        )[:3]

        return {
            "raw_score": raw_score,
            "normalized_score": normalized_score,
            "is_anomalous": raw_score <= self.threshold,
            "top_contributors": contributors,
        }


shared_anomaly_model = AnomalyDetectionModel()
