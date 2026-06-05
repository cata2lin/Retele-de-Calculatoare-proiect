"""Logger pentru cererile analizate: salveaza in baza de date si scrie o linie lizibila in fisier."""

import json
from datetime import datetime

import config
import baza_date


class RequestLogger:
    """Inregistreaza fiecare cerere analizata: in SQLite si intr-un fisier text."""

    def __init__(self):
        baza_date.init_db()

    def log_request(
        self,
        *,
        meta,
        features,
        rule_result,
        anomaly_result,
        llm_result,
        decision,
        status_code,
        latency_ms,
        response_size,
        blocked,
    ):
        """Salveaza cererea in baza de date si in fisierul de log, apoi intoarce record-ul."""
        timestamp = datetime.now().isoformat(timespec="seconds")

        # Daca LLM-ul nu a fost apelat, scorul lui nu intra in calcul (ramane 0).
        llm_score = llm_result["risk_score"] if llm_result else 0

        record = {
            "timestamp": timestamp,
            "ip": meta.get("ip"),
            "method": meta.get("method"),
            "path": meta.get("path"),
            "query": meta.get("query"),
            "user_agent": meta.get("user_agent"),
            "body_size": meta.get("body_size"),
            "status_code": status_code,
            "latency_ms": latency_ms,
            "response_size": response_size,
            "rule_score": rule_result["rule_score"],
            "anomaly_score": anomaly_result["anomaly_score"],
            "llm_score": llm_score,
            "final_score": decision["final_score"],
            "verdict": decision["verdict"],
            "top_category": decision["top_category"],
            "categories": json.dumps(decision["categories"]),
            "reason": decision["reason"],
            "possible_intent": decision["possible_intent"],
            "recommended_action": decision["recommended_action"],
            "is_anomaly": 1 if anomaly_result["is_anomaly"] else 0,
            "blocked": 1 if blocked else 0,
        }

        baza_date.insert_request(record)

        self._write_log_line(record, decision)

        return record

    def _write_log_line(self, record, decision):
        """Adauga o linie lizibila in fisierul de log. O eroare aici nu opreste aplicatia."""
        # Categoriile sunt salvate ca JSON in record; pentru fisier le vrem listate normal.
        categories = decision.get("categories", [])
        if categories:
            categorii_text = ", ".join(categories)
        else:
            categorii_text = "fara"

        line = (
            "[{timestamp}] {ip} {method} {path} -> {status} "
            "| scor={final} ({verdict}) | {categorii}\n"
        ).format(
            timestamp=record["timestamp"],
            ip=record["ip"],
            method=record["method"],
            path=record["path"],
            status=record["status_code"],
            final=record["final_score"],
            verdict=record["verdict"],
            categorii=categorii_text,
        )

        try:
            # Ne asiguram ca folderul de loguri exista inainte de scriere.
            config.ensure_dirs()
            with open(config.LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line)
        except OSError as exc:
            # Daca scrierea in fisier esueaza, continuam: cererea e deja salvata in baza de date.
            print("Eroare la scrierea in fisierul de log:", exc)
