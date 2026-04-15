from sklearn.ensemble import IsolationForest
import pandas as pd
import numpy as np
from typing import List, Dict, Any
import joblib
import os

class AnomalyDetectionModel:
    def __init__(self):
        self.model = None
        self.model_path = "app/ml/isolation_forest.pkl"

    def load_model(self):
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
        else:
            self.model = IsolationForest(contamination=0.1, random_state=42)

    def save_model(self):
        joblib.dump(self.model, self.model_path)

    def train(self, data: List[Dict[str, Any]]):
        if not data:
            return

        df = pd.DataFrame(data)
        features = ['login_hour', 'location_lat', 'location_lon', 'typing_speed', 'failed_attempts']
        df = df[features].fillna(0)

        self.model.fit(df)
        self.save_model()

    def predict_anomaly_score(self, features: Dict[str, Any]) -> float:
        if self.model is None:
            self.load_model()

        df = pd.DataFrame([features])
        features_list = ['login_hour', 'location_lat', 'location_lon', 'typing_speed', 'failed_attempts']
        df = df[features_list].fillna(0)

        # IsolationForest returns -1 for outliers, 1 for inliers
        prediction = self.model.predict(df)[0]
        # Convert to anomaly score (0-1, higher is more anomalous)
        anomaly_score = 1 if prediction == -1 else 0
        return anomaly_score