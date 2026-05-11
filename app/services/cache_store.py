import json
import threading
from datetime import datetime, timedelta
from typing import Any, Optional

import redis


class CacheStore:
    def __init__(self, redis_url: str):
        self._redis_url = redis_url
        self._redis_client = None
        self._fallback_store = {}
        self._lock = threading.Lock()
        try:
            self._redis_client = redis.Redis.from_url(self._redis_url, decode_responses=True)
            self._redis_client.ping()
        except redis.RedisError:
            self._redis_client = None

    def _get_redis_client(self):
        if self._redis_client is None:
            self._redis_client = redis.Redis.from_url(self._redis_url, decode_responses=True)
        return self._redis_client

    def _purge_expired(self):
        now = datetime.utcnow()
        expired_keys = [key for key, item in self._fallback_store.items() if item["expires_at"] <= now]
        for key in expired_keys:
            self._fallback_store.pop(key, None)

    def get(self, key: str) -> Optional[str]:
        try:
            return self._get_redis_client().get(key)
        except redis.RedisError:
            self._redis_client = None
            with self._lock:
                self._purge_expired()
                item = self._fallback_store.get(key)
                return item["value"] if item else None

    def set(self, key: str, value: str) -> None:
        try:
            self._get_redis_client().set(key, value)
            return
        except redis.RedisError:
            self._redis_client = None
            with self._lock:
                self._fallback_store[key] = {
                    "value": value,
                    "expires_at": datetime.utcnow() + timedelta(days=3650),
                }

    def setex(self, key: str, ttl_seconds: int, value: str) -> None:
        try:
            self._get_redis_client().setex(key, ttl_seconds, value)
            return
        except redis.RedisError:
            self._redis_client = None
            with self._lock:
                self._fallback_store[key] = {
                    "value": value,
                    "expires_at": datetime.utcnow() + timedelta(seconds=ttl_seconds),
                }

    def delete(self, key: str) -> None:
        try:
            self._get_redis_client().delete(key)
            return
        except redis.RedisError:
            self._redis_client = None
            with self._lock:
                self._fallback_store.pop(key, None)

    def incr(self, key: str) -> int:
        try:
            return int(self._get_redis_client().incr(key))
        except redis.RedisError:
            self._redis_client = None
            with self._lock:
                self._purge_expired()
                item = self._fallback_store.get(key)
                current_value = int(item["value"]) if item else 0
                current_value += 1
                expires_at = item["expires_at"] if item else datetime.utcnow() + timedelta(minutes=5)
                self._fallback_store[key] = {
                    "value": str(current_value),
                    "expires_at": expires_at,
                }
                return current_value

    def expire(self, key: str, ttl_seconds: int) -> None:
        try:
            self._get_redis_client().expire(key, ttl_seconds)
            return
        except redis.RedisError:
            self._redis_client = None
            with self._lock:
                self._purge_expired()
                if key in self._fallback_store:
                    self._fallback_store[key]["expires_at"] = datetime.utcnow() + timedelta(seconds=ttl_seconds)

    def get_json(self, key: str) -> Optional[dict]:
        value = self.get(key)
        if value is None:
            return None
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return None
        return parsed if isinstance(parsed, dict) else None

    def set_json(self, key: str, ttl_seconds: int, value: dict) -> None:
        self.setex(key, ttl_seconds, json.dumps(value))
