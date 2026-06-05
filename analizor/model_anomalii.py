"""Detector de anomalii comportamentale bazat pe Isolation Forest."""

import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

import config


def _clamp(value, low, high):
    """Limiteaza o valoare in intervalul [low, high]."""
    return max(low, min(high, value))


# Etichete in romana pentru fiecare trasatura, folosite in mesajul de motivare
FEATURE_LABELS = {
    "requests_per_minute": "numarul de cereri pe minut",
    "unique_paths_per_minute": "numarul de cai distincte pe minut",
    "percentage_404": "procentul de raspunsuri 404",
    "average_response_size": "dimensiunea medie a raspunsului",
    "average_latency_ms": "latenta medie",
    "user_agent_length": "lungimea user-agent-ului",
    "number_of_query_parameters": "numarul de parametri din query",
    "path_depth": "adancimea caii",
    "body_size": "dimensiunea corpului cererii",
    "failed_login_count": "numarul de autentificari esuate",
}


class AnomalyDetector:
    """Invata tiparul de trafic normal si marcheaza abaterile."""

    def __init__(self):
        self.model = None
        self.feature_means = None
        self.feature_stds = None
        self.feature_order = config.FEATURE_ORDER

    def _generate_normal_samples(self, n=2000):
        """Genereaza trafic normal sintetic ca matrice (n, 10) in ordinea FEATURE_ORDER."""
        rng = np.random.default_rng(42)

        # Cereri pe minut: utilizator obisnuit, ritm scazut
        requests_per_minute = rng.integers(1, 16, size=n).astype(float)
        # Caile distincte nu pot depasi numarul de cereri din fereastra
        unique_paths_per_minute = rng.integers(1, 9, size=n).astype(float)
        unique_paths_per_minute = np.minimum(unique_paths_per_minute, requests_per_minute)
        # Trafic sanatos: foarte putine 404
        percentage_404 = rng.uniform(0.0, 0.1, size=n)
        average_response_size = rng.uniform(500, 5000, size=n)
        average_latency_ms = rng.uniform(5, 80, size=n)
        # User-agent de browser real, sir lung
        user_agent_length = rng.uniform(70, 140, size=n)
        number_of_query_parameters = rng.integers(0, 4, size=n).astype(float)
        path_depth = rng.integers(1, 5, size=n).astype(float)
        body_size = rng.uniform(0, 2000, size=n)
        # Aproape niciodata esecuri de autentificare la trafic normal
        failed_login_count = rng.integers(0, 2, size=n).astype(float)

        columns = {
            "requests_per_minute": requests_per_minute,
            "unique_paths_per_minute": unique_paths_per_minute,
            "percentage_404": percentage_404,
            "average_response_size": average_response_size,
            "average_latency_ms": average_latency_ms,
            "user_agent_length": user_agent_length,
            "number_of_query_parameters": number_of_query_parameters,
            "path_depth": path_depth,
            "body_size": body_size,
            "failed_login_count": failed_login_count,
        }

        # Asamblam matricea respectand strict ordinea din config
        matrix = np.column_stack([columns[k] for k in self.feature_order])
        # Nicio trasatura nu poate fi negativa
        return np.clip(matrix, 0.0, None)

    def train(self):
        """Antreneaza modelul pe trafic normal sintetic si il salveaza pe disc."""
        config.ensure_dirs()
        samples = self._generate_normal_samples()

        model = IsolationForest(
            n_estimators=200,
            contamination=0.05,
            random_state=42,
        )
        model.fit(samples)

        means = samples.mean(axis=0)
        stds = samples.std(axis=0)

        self.model = model
        self.feature_means = means
        self.feature_stds = stds

        payload = {
            "model": model,
            "means": means,
            "stds": stds,
            "order": self.feature_order,
        }
        joblib.dump(payload, config.ANOMALY_MODEL_PATH)

    def load(self):
        """Incarca modelul de pe disc, sau il antreneaza daca lipseste."""
        if config.ANOMALY_MODEL_PATH.exists():
            payload = joblib.load(config.ANOMALY_MODEL_PATH)
            self.model = payload["model"]
            self.feature_means = payload["means"]
            self.feature_stds = payload["stds"]
            self.feature_order = payload["order"]
        else:
            self.train()

    def score(self, features):
        """Evalueaza un dictionar de caracteristici si intoarce scorul de anomalie."""
        if self.model is None:
            self.load()

        # Construim vectorul respectand ordinea fixa a trasaturilor
        x = [float(features.get(k, 0.0)) for k in self.feature_order]

        decision = float(self.model.decision_function([x])[0])
        is_anomaly = self.model.predict([x])[0] == -1
        anomaly_score = int(_clamp(round(50 - decision * 100), 0, 100))

        if is_anomaly:
            # Cautam trasatura cu cea mai mare deviere pozitiva fata de normal.
            # Std are un minim mic pentru a evita impartirea la zero.
            arr = np.array(x, dtype=float)
            safe_stds = np.maximum(self.feature_stds, 1e-6)
            z_scores = (arr - self.feature_means) / safe_stds

            worst_index = int(np.argmax(z_scores))
            worst_key = self.feature_order[worst_index]
            label = FEATURE_LABELS.get(worst_key, worst_key)
            reason = "Comportament neobisnuit: " + label + " mult peste tiparul normal."
        else:
            reason = "Comportament in limitele tiparului normal."

        return {
            "is_anomaly": bool(is_anomaly),
            "raw_score": decision,
            "anomaly_score": anomaly_score,
            "reason": reason,
        }


# Instanta unica, incarcata la prima cerere (lazy)
_detector = None


def get_detector():
    """Intoarce detectorul singleton, incarcandu-l la prima utilizare."""
    global _detector
    if _detector is None:
        _detector = AnomalyDetector()
        _detector.load()
    return _detector


if __name__ == "__main__":
    detector = AnomalyDetector()
    detector.train()
    print("Modelul de anomalii a fost antrenat si salvat in:", config.ANOMALY_MODEL_PATH)
