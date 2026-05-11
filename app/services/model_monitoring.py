import json
import math
import os
import threading
import time
from datetime import datetime
from typing import Any, Dict, List

import numpy as np
from sqlalchemy.orm import Session

from app.config import settings
from app.database.models import LoginAttempt
from app.ml.model import FEATURE_COLUMNS, AnomalyDetectionModel, shared_anomaly_model
from app.ml.registry import model_registry
from app.utils.helpers import calculate_distance


class ModelMonitoringService:
    """Small artifact-backed service for model metrics, drift, retraining, and prediction telemetry."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.metadata_path = settings.model_metadata_path
        self.monitoring_log_path = settings.model_monitoring_log_path

    def get_status(self, db: Session) -> Dict[str, Any]:
        metrics = self._classification_metrics(db)
        confusion_matrix = self.get_confusion_matrix(db)
        drift = self.get_drift(db)
        metadata = self._load_metadata()
        monitoring = self.get_monitoring(db)
        active_model = model_registry.get(metadata.get("active_model_key"))
        return {
            "model_name": active_model.name,
            "active_model_key": active_model.key,
            "available_models": model_registry.list_models(),
            "version": metadata.get("current_version", "v1.0"),
            **metrics,
            "confusion_matrix": confusion_matrix,
            "inference_time_ms": monitoring["average_latency_ms"],
            "dataset_size": db.query(LoginAttempt).count(),
            "last_trained": metadata.get("last_trained") or self._fallback_timestamp(),
            "drift_detected": drift["drift_detected"],
            "drift_score": drift["drift_score"],
            "status": "degraded" if drift["drift_detected"] else "healthy",
        }

    def get_drift(self, db: Session) -> Dict[str, Any]:
        metadata = self._load_metadata()
        baseline = metadata.get("baseline_distributions") or self._build_baseline(db)
        if not self._baseline_has_bin_edges(baseline):
            baseline = self._build_baseline(db)
        production_query = db.query(LoginAttempt)
        last_trained_at = self._parse_datetime(metadata.get("last_trained"))
        if last_trained_at is not None:
            production_query = production_query.filter(LoginAttempt.timestamp > last_trained_at)
        recent_attempts = production_query.order_by(LoginAttempt.timestamp.desc()).limit(500).all()
        if last_trained_at is not None and len(recent_attempts) < 20:
            return {
                "drift_detected": False,
                "drift_level": "low",
                "drift_score": 0.0,
                "affected_features": [],
                "sample_size": len(recent_attempts),
                "timestamp": datetime.utcnow(),
            }
        production_rows = self._feature_rows_from_attempts(list(reversed(recent_attempts)))
        production = self._distribution_summary(production_rows, reference_summary=baseline)

        affected_features: List[Dict[str, Any]] = []
        feature_scores: List[float] = []
        for feature in FEATURE_COLUMNS:
            baseline_feature = baseline.get(feature)
            production_feature = production.get(feature)
            if not baseline_feature or not production_feature:
                continue
            psi = self._population_stability_index(
                baseline_feature["histogram"],
                production_feature["histogram"],
            )
            kl = self._kl_divergence(
                baseline_feature["histogram"],
                production_feature["histogram"],
            )
            # PSI is the primary drift signal because it is interpretable for feature
            # distribution monitoring. KL is kept as a small normalized secondary
            # signal for extra sensitivity without saturating the score instantly.
            normalized_psi = min(1.0, psi)
            normalized_kl = math.tanh(kl / 5)
            score = (normalized_psi * 0.8) + (normalized_kl * 0.2)
            feature_scores.append(score)
            if score >= settings.drift_threshold:
                affected_features.append({
                    "feature": feature,
                    "score": round(score, 4),
                    "psi": round(psi, 4),
                    "kl_divergence": round(kl, 4),
                })

        # Use the mean across features so a single noisy feature does not mark the
        # entire model as drifted by itself.
        drift_score = float(np.mean(feature_scores)) if feature_scores else 0.0
        drift_level = self._drift_level(drift_score)
        return {
            "drift_detected": drift_score >= settings.drift_threshold,
            "drift_level": drift_level,
            "drift_score": round(float(drift_score), 4),
            "affected_features": affected_features,
            "sample_size": len(recent_attempts),
            "timestamp": datetime.utcnow(),
        }

    def retrain(self, db: Session) -> Dict[str, Any]:
        started = time.perf_counter()
        attempts = db.query(LoginAttempt).filter(LoginAttempt.success == True).order_by(
            LoginAttempt.timestamp.asc()
        ).all()
        rows = self._feature_rows_from_attempts(attempts)
        if len(rows) < settings.min_training_samples:
            return {
                "success": False,
                "new_version": self._load_metadata().get("current_version", "v1.0"),
                "training_samples": len(rows),
                "training_time_seconds": round(time.perf_counter() - started, 4),
                "metrics": self._classification_metrics(db),
                "error": "Not enough successful login data to retrain model",
            }

        with self._lock:
            next_version = self._next_version()
            candidate_model = AnomalyDetectionModel()
            candidate_model.model_path = shared_anomaly_model.model_path
            trained = candidate_model.train(rows)
            if trained:
                # Swap the already-trained model objects in memory after fitting to avoid serving a half-trained model.
                shared_anomaly_model.model = candidate_model.model
                shared_anomaly_model.scaler = candidate_model.scaler
                shared_anomaly_model.threshold = candidate_model.threshold
                shared_anomaly_model.score_min = candidate_model.score_min
                shared_anomaly_model.score_max = candidate_model.score_max

            metadata = self._load_metadata()
            metrics = self._classification_metrics(db)
            history_item = {
                "version": next_version,
                "trained_at": datetime.utcnow().isoformat(),
                "dataset_size": len(rows),
                "accuracy": metrics["accuracy"],
            }
            metadata["current_version"] = next_version
            metadata["last_trained"] = history_item["trained_at"]
            # Model training stays on successful logins, but drift monitoring should
            # reset against recent production traffic after retraining. Otherwise a
            # retrained model can still immediately compare against an old baseline.
            drift_attempts = db.query(LoginAttempt).order_by(LoginAttempt.timestamp.desc()).limit(1000).all()
            drift_rows = self._feature_rows_from_attempts(list(reversed(drift_attempts)))
            metadata["baseline_distributions"] = self._distribution_summary(drift_rows or rows)
            metadata.setdefault("history", []).append(history_item)
            self._save_metadata(metadata)

        return {
            "success": bool(trained),
            "new_version": next_version,
            "training_samples": len(rows),
            "training_time_seconds": round(time.perf_counter() - started, 4),
            "metrics": metrics,
        }

    def get_history(self) -> List[Dict[str, Any]]:
        metadata = self._load_metadata()
        history = metadata.get("history", [])
        return history or [{
            "version": metadata.get("current_version", "v1.0"),
            "trained_at": metadata.get("last_trained") or self._fallback_timestamp(),
            "dataset_size": 0,
            "accuracy": 0.0,
        }]

    def explain(self, login_features: Dict[str, Any], db: Session) -> Dict[str, Any]:
        normalized = self._normalize_input_features(login_features)
        prediction = model_registry.get(self._load_metadata().get("active_model_key")).predict_anomaly_score(normalized)
        baseline = self._load_metadata().get("baseline_distributions") or self._build_baseline(db)

        factors: List[Dict[str, Any]] = []
        for feature in FEATURE_COLUMNS:
            value = float(normalized.get(feature, 0) or 0)
            summary = baseline.get(feature, {})
            mean_value = float(summary.get("mean", 0.0) or 0)
            std_value = float(summary.get("std", 0.0) or 0)
            impact = abs(value - mean_value) / max(std_value, 1.0)
            factors.append({
                "feature": feature,
                "impact": round(min(1.0, impact / 3), 4),
                "description": self._factor_description(feature, value, mean_value),
            })

        top_factors = sorted(factors, key=lambda item: item["impact"], reverse=True)[:5]
        risk_score = float(prediction.get("normalized_score", 0.0))
        return {
            "risk_score": round(risk_score, 4),
            "top_factors": top_factors,
            "explanation": self._human_explanation(top_factors, risk_score),
        }

    def get_monitoring(self, db: Session) -> Dict[str, Any]:
        entries = self._read_prediction_logs(limit=500)
        total_predictions = len(entries)
        anomalies = [entry for entry in entries if entry.get("risk_score", 0) >= 40]
        latencies = [float(entry.get("latency_ms", 0.0) or 0.0) for entry in entries]
        recent_attempts = db.query(LoginAttempt).order_by(LoginAttempt.timestamp.desc()).limit(100).all()
        return {
            "status": "healthy",
            "total_predictions": total_predictions,
            "average_latency_ms": round(float(np.mean(latencies)) if latencies else 0.0, 3),
            "p95_latency_ms": round(float(np.percentile(latencies, 95)) if latencies else 0.0, 3),
            "anomaly_rate": round(len(anomalies) / max(total_predictions, 1), 4),
            "recent_prediction_count": len(recent_attempts),
            "recent_block_rate": round(
                sum(1 for attempt in recent_attempts if attempt.decision == "block") / max(len(recent_attempts), 1),
                4,
            ),
            "timestamp": datetime.utcnow(),
        }

    def get_confusion_matrix(self, db: Session) -> Dict[str, Any]:
        counts = self._confusion_counts(db)
        total = sum(counts.values())
        return {
            "labels": ["normal", "anomaly"],
            "matrix": [
                [counts["tn"], counts["fp"]],
                [counts["fn"], counts["tp"]],
            ],
            "counts": counts,
            "total": total,
            "generated_at": datetime.utcnow(),
        }

    def log_prediction(self, risk_score: float, decision: str, latency_ms: float, features: Dict[str, Any]) -> None:
        os.makedirs(os.path.dirname(self.monitoring_log_path), exist_ok=True)
        record = {
            "timestamp": datetime.utcnow().isoformat(),
            "risk_score": risk_score,
            "decision": decision,
            "latency_ms": round(latency_ms, 4),
            "features": {key: features.get(key) for key in FEATURE_COLUMNS},
        }
        try:
            with open(self.monitoring_log_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, default=str) + "\n")
        except OSError:
            # Prediction should never fail because telemetry could not be written.
            return

    def _classification_metrics(self, db: Session) -> Dict[str, float]:
        attempts = db.query(LoginAttempt).all()
        if not attempts:
            return {
                "accuracy": 0.0,
                "precision": 0.0,
                "recall": 0.0,
                "f1_score": 0.0,
                "roc_auc": 0.0,
                "false_positive_rate": 0.0,
            }

        counts = self._confusion_counts_from_attempts(attempts)
        tp = counts["tp"]
        fp = counts["fp"]
        tn = counts["tn"]
        fn = counts["fn"]
        positives: List[float] = []
        negatives: List[float] = []
        for attempt in attempts:
            actual_bad = not bool(attempt.success)
            (positives if actual_bad else negatives).append((attempt.risk_score or 0.0) / 100)

        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        f1_score = 2 * precision * recall / max(precision + recall, 1e-9)
        return {
            "accuracy": round((tp + tn) / max(len(attempts), 1), 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1_score, 4),
            "roc_auc": round(self._rank_auc(positives, negatives), 4),
            "false_positive_rate": round(fp / max(fp + tn, 1), 4),
        }

    def _confusion_counts(self, db: Session) -> Dict[str, int]:
        return self._confusion_counts_from_attempts(db.query(LoginAttempt).all())

    def _confusion_counts_from_attempts(self, attempts: List[LoginAttempt]) -> Dict[str, int]:
        counts = {"tn": 0, "fp": 0, "fn": 0, "tp": 0}
        for attempt in attempts:
            actual_bad = not bool(attempt.success)
            predicted_bad = (attempt.risk_score or 0.0) >= 40 or attempt.decision == "block"
            if actual_bad and predicted_bad:
                counts["tp"] += 1
            elif not actual_bad and predicted_bad:
                counts["fp"] += 1
            elif not actual_bad and not predicted_bad:
                counts["tn"] += 1
            else:
                counts["fn"] += 1
        return counts

    def _feature_rows_from_attempts(self, attempts: List[LoginAttempt]) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        last_success_by_user: Dict[int, LoginAttempt] = {}
        for attempt in attempts:
            previous = last_success_by_user.get(attempt.user_id)
            interval_hours = 0.0
            distance = 0.0
            if previous:
                interval_hours = max(0.0, (attempt.timestamp - previous.timestamp).total_seconds() / 3600)
                if (
                    attempt.location_lat is not None and attempt.location_lon is not None
                    and previous.location_lat is not None and previous.location_lon is not None
                ):
                    distance = calculate_distance(
                        attempt.location_lat,
                        attempt.location_lon,
                        previous.location_lat,
                        previous.location_lon,
                    )
            rows.append({
                "login_hour": attempt.timestamp.hour + attempt.timestamp.minute / 60,
                "location_lat": attempt.location_lat or 0,
                "location_lon": attempt.location_lon or 0,
                "typing_speed": attempt.typing_speed or 0,
                "failed_attempts": 0 if attempt.success else 1,
                "ip_risk_score": 1 if not attempt.success else 0,
                "device_usage_frequency": 0,
                "login_interval_hours": interval_hours,
                "geo_distance_from_last_login": distance,
            })
            if attempt.success:
                last_success_by_user[attempt.user_id] = attempt
        return rows

    def _distribution_summary(
        self,
        rows: List[Dict[str, Any]],
        reference_summary: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        summary: Dict[str, Any] = {}
        for feature in FEATURE_COLUMNS:
            values = np.array([float(row.get(feature, 0) or 0) for row in rows], dtype=float)
            if values.size == 0:
                continue
            reference_feature = (reference_summary or {}).get(feature, {})
            reference_edges = reference_feature.get("bin_edges")
            if reference_edges and len(reference_edges) >= 2:
                bin_edges = np.array(reference_edges, dtype=float)
                histogram, _ = np.histogram(values, bins=bin_edges)
            else:
                histogram, bin_edges = np.histogram(values, bins=10)
            probabilities = (histogram + 1e-6) / max(float(np.sum(histogram)), 1.0)
            summary[feature] = {
                "mean": float(np.mean(values)),
                "std": float(np.std(values)),
                "histogram": probabilities.tolist(),
                "bin_edges": bin_edges.tolist(),
            }
        return summary

    def _build_baseline(self, db: Session) -> Dict[str, Any]:
        attempts = db.query(LoginAttempt).order_by(LoginAttempt.timestamp.asc()).limit(1000).all()
        return self._distribution_summary(self._feature_rows_from_attempts(attempts))

    def _baseline_has_bin_edges(self, baseline: Dict[str, Any]) -> bool:
        if not baseline:
            return False
        for feature in FEATURE_COLUMNS:
            feature_summary = baseline.get(feature)
            if feature_summary and not feature_summary.get("bin_edges"):
                return False
        return True

    def _drift_level(self, score: float) -> str:
        if score < 0.2:
            return "low"
        if score < 0.5:
            return "moderate"
        if score < 0.75:
            return "high"
        return "critical"

    def _population_stability_index(self, expected: List[float], actual: List[float]) -> float:
        expected_arr = np.array(expected, dtype=float) + 1e-6
        actual_arr = np.array(actual, dtype=float) + 1e-6
        return float(np.sum((actual_arr - expected_arr) * np.log(actual_arr / expected_arr)))

    def _kl_divergence(self, expected: List[float], actual: List[float]) -> float:
        expected_arr = np.array(expected, dtype=float) + 1e-6
        actual_arr = np.array(actual, dtype=float) + 1e-6
        return float(np.sum(actual_arr * np.log(actual_arr / expected_arr)))

    def _rank_auc(self, positives: List[float], negatives: List[float]) -> float:
        if not positives or not negatives:
            return 0.0
        wins = 0.0
        for positive in positives:
            for negative in negatives:
                if positive > negative:
                    wins += 1
                elif math.isclose(positive, negative):
                    wins += 0.5
        return wins / (len(positives) * len(negatives))

    def _normalize_input_features(self, login_features: Dict[str, Any]) -> Dict[str, Any]:
        source = login_features.get("login_features", login_features)
        return {
            "login_hour": source.get("login_hour", source.get("hour", 0)),
            "location_lat": source.get("location_lat", 0),
            "location_lon": source.get("location_lon", 0),
            "typing_speed": source.get("typing_speed", 0),
            "failed_attempts": source.get("failed_attempts", 0),
            "ip_risk_score": source.get("ip_risk_score", 0),
            "device_usage_frequency": source.get("device_usage_frequency", 0),
            "login_interval_hours": source.get("login_interval_hours", 0),
            "geo_distance_from_last_login": source.get(
                "geo_distance_from_last_login",
                source.get("geo_distance", 0),
            ),
        }

    def _factor_description(self, feature: str, value: float, mean_value: float) -> str:
        direction = "above" if value >= mean_value else "below"
        return f"{feature.replace('_', ' ')} is {direction} the learned baseline"

    def _human_explanation(self, factors: List[Dict[str, Any]], risk_score: float) -> str:
        if not factors:
            return "No strong anomalous factors were detected."
        names = ", ".join(item["feature"].replace("_", " ") for item in factors[:3])
        return f"Risk {risk_score:.2f} is mainly driven by {names}."

    def _read_prediction_logs(self, limit: int) -> List[Dict[str, Any]]:
        if not os.path.exists(self.monitoring_log_path):
            return []
        try:
            with open(self.monitoring_log_path, "r", encoding="utf-8") as handle:
                lines = handle.readlines()[-limit:]
            return [json.loads(line) for line in lines if line.strip()]
        except (OSError, ValueError):
            return []

    def _load_metadata(self) -> Dict[str, Any]:
        if not os.path.exists(self.metadata_path):
            return {"current_version": "v1.0", "history": []}
        try:
            with open(self.metadata_path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, ValueError):
            return {"current_version": "v1.0", "history": []}

    def _save_metadata(self, metadata: Dict[str, Any]) -> None:
        os.makedirs(os.path.dirname(self.metadata_path), exist_ok=True)
        with open(self.metadata_path, "w", encoding="utf-8") as handle:
            json.dump(metadata, handle, indent=2, default=str)

    def _next_version(self) -> str:
        version = self._load_metadata().get("current_version", "v1.0").lstrip("v")
        major, minor = (version.split(".") + ["0"])[:2]
        return f"v{int(major)}.{int(minor) + 1}"

    def _fallback_timestamp(self) -> str:
        model_path = shared_anomaly_model.model_path
        if os.path.exists(model_path):
            return datetime.utcfromtimestamp(os.path.getmtime(model_path)).isoformat()
        return datetime.utcnow().isoformat()

    def _parse_datetime(self, value: Any) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(str(value))
        except ValueError:
            return None


model_monitoring_service = ModelMonitoringService()
