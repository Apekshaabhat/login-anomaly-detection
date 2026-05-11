from abc import ABC, abstractmethod
from typing import Any, Dict, List

from app.ml.model import shared_anomaly_model


class PredictionModelAdapter(ABC):
    """Stable interface for current and future anomaly model implementations."""

    name: str
    key: str
    available: bool = True

    @abstractmethod
    def predict_anomaly_score(self, features: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def train(self, rows: List[Dict[str, Any]]) -> bool:
        raise NotImplementedError

    def metadata(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "available": self.available,
        }


class IsolationForestAdapter(PredictionModelAdapter):
    key = "isolation_forest"
    name = "Isolation Forest"

    def predict_anomaly_score(self, features: Dict[str, Any]) -> Dict[str, Any]:
        return shared_anomaly_model.predict_anomaly_score(features)

    def train(self, rows: List[Dict[str, Any]]) -> bool:
        return bool(shared_anomaly_model.train(rows))


class FutureModelAdapter(PredictionModelAdapter):
    """Registry placeholder for models that can be plugged in later without changing API contracts."""

    available = False

    def __init__(self, key: str, name: str) -> None:
        self.key = key
        self.name = name

    def predict_anomaly_score(self, features: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "raw_score": 0.0,
            "normalized_score": 0.0,
            "is_anomalous": False,
            "top_contributors": [],
            "error": f"{self.name} is registered but not configured",
        }

    def train(self, rows: List[Dict[str, Any]]) -> bool:
        return False


class ModelRegistry:
    def __init__(self) -> None:
        self._models: Dict[str, PredictionModelAdapter] = {}
        self._default_key = "isolation_forest"
        self.register(IsolationForestAdapter())
        self.register(FutureModelAdapter("xgboost", "XGBoost"))
        self.register(FutureModelAdapter("autoencoder", "Autoencoder"))
        self.register(FutureModelAdapter("lstm", "LSTM"))

    def register(self, adapter: PredictionModelAdapter) -> None:
        self._models[adapter.key] = adapter

    def get(self, key: str | None = None) -> PredictionModelAdapter:
        return self._models.get(key or self._default_key, self._models[self._default_key])

    def list_models(self) -> List[Dict[str, Any]]:
        return [adapter.metadata() for adapter in self._models.values()]

    @property
    def default_model_key(self) -> str:
        return self._default_key


model_registry = ModelRegistry()
