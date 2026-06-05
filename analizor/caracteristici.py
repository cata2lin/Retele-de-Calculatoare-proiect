"""Extragerea caracteristicilor comportamentale per IP pe o fereastra glisanta."""

import time
import threading
from collections import defaultdict, deque

import config


class FeatureExtractor:
    """Mentine istoricul recent al fiecarui IP si calculeaza cele 10 caracteristici."""

    def __init__(self, window_seconds=None):
        self.window_seconds = window_seconds or config.WINDOW_SECONDS
        # Pentru fiecare IP tinem un deque de evenimente din ultimele "window_seconds".
        self.events = defaultdict(deque)
        self.lock = threading.Lock()

    def _prune(self, ip, now):
        """Scoate evenimentele mai vechi decat fereastra; presupune lock deja luat."""
        window = self.events[ip]
        cutoff = now - self.window_seconds
        while window and window[0]["timestamp"] < cutoff:
            window.popleft()
        # Daca IP-ul nu mai are evenimente, eliberam intrarea ca sa nu acumulam memorie.
        if not window:
            del self.events[ip]

    def record_event(self, ip, path, status_code, latency_ms, response_size, is_failed_login):
        """Inregistreaza un eveniment incheiat (cu status si latenta) pentru un IP."""
        now = time.time()
        with self.lock:
            self._prune(ip, now)
            self.events[ip].append({
                "timestamp": now,
                "path": path,
                "status_code": status_code,
                "latency_ms": latency_ms,
                "response_size": response_size,
                "is_failed_login": bool(is_failed_login),
            })

    def extract(self, ip, meta):
        """Calculeaza dictionarul cu cele 10 caracteristici din FEATURE_ORDER pentru cererea curenta."""
        now = time.time()
        with self.lock:
            self._prune(ip, now)
            # Copiem evenimentele sub lock ca sa eliberam repede zona critica.
            window = list(self.events.get(ip, ()))

        # Fereastra contine doar cereri ANTERIOARE: cererea curenta nu are inca status
        # sau latenta (acelea se cunosc abia dupa raspunsul backend-ului, prin record_event).
        count = len(window)

        # Caile distincte din fereastra reunite cu calea curenta.
        current_path = meta.get("path", "") or ""
        paths = {ev["path"] for ev in window}
        paths.add(current_path)

        if count > 0:
            num_404 = sum(1 for ev in window if ev["status_code"] == 404)
            percentage_404 = num_404 / count
            average_response_size = sum(ev["response_size"] for ev in window) / count
            average_latency_ms = sum(ev["latency_ms"] for ev in window) / count
            failed_login_count = sum(1 for ev in window if ev["is_failed_login"])
        else:
            percentage_404 = 0.0
            average_response_size = 0.0
            average_latency_ms = 0.0
            failed_login_count = 0

        user_agent = meta.get("user_agent", "") or ""

        query = meta.get("query", "") or ""
        if query:
            number_of_query_parameters = sum(1 for seg in query.split("&") if seg)
        else:
            number_of_query_parameters = 0

        path_depth = sum(1 for seg in current_path.split("/") if seg)

        features = {
            # +1 fiindca numaram si cererea curenta, nu doar istoricul.
            "requests_per_minute": count + 1,
            "unique_paths_per_minute": len(paths),
            "percentage_404": round(percentage_404, 4),
            "average_response_size": round(average_response_size, 2),
            "average_latency_ms": round(average_latency_ms, 2),
            "user_agent_length": len(user_agent),
            "number_of_query_parameters": number_of_query_parameters,
            "path_depth": path_depth,
            "body_size": int(meta.get("body_size", 0) or 0),
            "failed_login_count": failed_login_count,
        }
        return features
