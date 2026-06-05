"""Acces la baza de date SQLite: salvarea cererilor analizate si gestiunea IP-urilor blocate."""

import json
import sqlite3
import threading
from datetime import datetime, timedelta

import config

# Conexiune unica reutilizata din mai multe fire (proxy-ul e async, dar scrierile vin din thread-uri).
# check_same_thread=False ne lasa sa folosim aceeasi conexiune; protejam scrierile cu un Lock.
_conn = None
_write_lock = threading.Lock()


def _now():
    """Momentul curent ca string ISO, fara fractiuni de secunda."""
    return datetime.now().isoformat(timespec="seconds")


def _rows_to_dicts(rows):
    """Converteste o lista de sqlite3.Row in lista de dictionare obisnuite."""
    return [dict(r) for r in rows]


def init_db():
    """Creeaza folderele si tabelele daca nu exista si pregateste conexiunea."""
    global _conn
    config.ensure_dirs()

    _conn = sqlite3.connect(str(config.DB_PATH), check_same_thread=False)
    _conn.row_factory = sqlite3.Row

    with _write_lock:
        _conn.execute(
            """
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                ip TEXT,
                method TEXT,
                path TEXT,
                query TEXT,
                user_agent TEXT,
                body_size INTEGER,
                status_code INTEGER,
                latency_ms REAL,
                response_size INTEGER,
                rule_score INTEGER,
                anomaly_score INTEGER,
                llm_score INTEGER,
                final_score INTEGER,
                verdict TEXT,
                top_category TEXT,
                categories TEXT,
                reason TEXT,
                possible_intent TEXT,
                recommended_action TEXT,
                is_anomaly INTEGER,
                blocked INTEGER
            )
            """
        )
        _conn.execute(
            """
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip TEXT PRIMARY KEY,
                blocked_until TEXT,
                reason TEXT,
                created_at TEXT
            )
            """
        )
        # Indecsii ajuta la interogarile dese (cele mai recente cereri si filtrarea dupa scor).
        _conn.execute("CREATE INDEX IF NOT EXISTS idx_requests_id ON requests(id)")
        _conn.execute("CREATE INDEX IF NOT EXISTS idx_requests_ip ON requests(ip)")
        _conn.commit()


def _require_conn():
    """Se asigura ca init_db a fost apelat inainte de orice operatie."""
    if _conn is None:
        init_db()
    return _conn


def insert_request(record):
    """Salveaza o cerere analizata si intoarce id-ul rand-ului nou."""
    conn = _require_conn()

    # categories e o lista in memorie, dar in tabel se pastreaza ca text JSON.
    categories = record.get("categories", [])
    if not isinstance(categories, str):
        categories = json.dumps(categories)

    is_anomaly = 1 if record.get("is_anomaly") else 0
    blocked = 1 if record.get("blocked") else 0

    timestamp = record.get("timestamp") or _now()

    values = (
        timestamp,
        record.get("ip"),
        record.get("method"),
        record.get("path"),
        record.get("query"),
        record.get("user_agent"),
        record.get("body_size"),
        record.get("status_code"),
        record.get("latency_ms"),
        record.get("response_size"),
        record.get("rule_score"),
        record.get("anomaly_score"),
        record.get("llm_score"),
        record.get("final_score"),
        record.get("verdict"),
        record.get("top_category"),
        categories,
        record.get("reason"),
        record.get("possible_intent"),
        record.get("recommended_action"),
        is_anomaly,
        blocked,
    )

    with _write_lock:
        cur = conn.execute(
            """
            INSERT INTO requests (
                timestamp, ip, method, path, query, user_agent, body_size,
                status_code, latency_ms, response_size, rule_score, anomaly_score,
                llm_score, final_score, verdict, top_category, categories, reason,
                possible_intent, recommended_action, is_anomaly, blocked
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )
        conn.commit()
        return cur.lastrowid


def recent_requests(limit=100, min_score=0):
    """Cele mai recente cereri cu scor final cel putin min_score, ordonate descrescator."""
    conn = _require_conn()
    rows = conn.execute(
        """
        SELECT * FROM requests
        WHERE final_score >= ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (min_score, limit),
    ).fetchall()
    return _rows_to_dicts(rows)


def top_ips(limit=20):
    """IP-urile cele mai active/periculoase (doar cele cu scor peste 30), dupa scorul maxim."""
    conn = _require_conn()
    rows = conn.execute(
        """
        SELECT
            ip,
            COUNT(*) AS total,
            MAX(final_score) AS max_score,
            ROUND(AVG(final_score)) AS avg_score,
            GROUP_CONCAT(DISTINCT top_category) AS categories,
            MAX(timestamp) AS last_seen
        FROM requests
        WHERE final_score > 30
        GROUP BY ip
        ORDER BY max_score DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return _rows_to_dicts(rows)


def category_counts():
    """Numarul de cereri pe fiecare categorie, excluzand cererile normale."""
    conn = _require_conn()
    rows = conn.execute(
        """
        SELECT top_category AS category, COUNT(*) AS count
        FROM requests
        WHERE top_category IS NOT NULL AND top_category != ?
        GROUP BY top_category
        ORDER BY count DESC
        """,
        (config.CAT_NORMAL,),
    ).fetchall()
    return _rows_to_dicts(rows)


def verdict_counts():
    """Numarul de cereri pe fiecare verdict."""
    conn = _require_conn()
    rows = conn.execute(
        """
        SELECT verdict, COUNT(*) AS count
        FROM requests
        GROUP BY verdict
        ORDER BY count DESC
        """
    ).fetchall()
    return _rows_to_dicts(rows)


def stats_summary():
    """Sumar global pentru dashboard: totaluri pe niveluri de risc si anomalii."""
    conn = _require_conn()
    now = _now()

    row = conn.execute(
        """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN final_score > 30 THEN 1 ELSE 0 END) AS suspecte,
            SUM(CASE WHEN final_score > 60 THEN 1 ELSE 0 END) AS risc_ridicat,
            SUM(CASE WHEN final_score > 80 THEN 1 ELSE 0 END) AS critice,
            SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) AS anomalii
        FROM requests
        """
    ).fetchone()

    blocate_row = conn.execute(
        "SELECT COUNT(*) AS blocate FROM blocked_ips WHERE blocked_until > ?",
        (now,),
    ).fetchone()

    return {
        "total": row["total"] or 0,
        "suspecte": row["suspecte"] or 0,
        "risc_ridicat": row["risc_ridicat"] or 0,
        "critice": row["critice"] or 0,
        "blocate": blocate_row["blocate"] or 0,
        "anomalii": row["anomalii"] or 0,
    }


def is_blocked(ip):
    """Spune daca IP-ul are o blocare inca activa."""
    conn = _require_conn()
    row = conn.execute(
        "SELECT 1 FROM blocked_ips WHERE ip = ? AND blocked_until > ?",
        (ip, _now()),
    ).fetchone()
    return row is not None


def block_ip(ip, minutes, reason):
    """Blocheaza un IP pentru un numar de minute (suprascrie o blocare existenta)."""
    conn = _require_conn()
    now = datetime.now()
    blocked_until = (now + timedelta(minutes=minutes)).isoformat(timespec="seconds")
    created_at = now.isoformat(timespec="seconds")

    with _write_lock:
        conn.execute(
            """
            REPLACE INTO blocked_ips (ip, blocked_until, reason, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (ip, blocked_until, reason, created_at),
        )
        conn.commit()


def unblock_expired():
    """Sterge din tabel blocarile care au expirat."""
    conn = _require_conn()
    with _write_lock:
        conn.execute("DELETE FROM blocked_ips WHERE blocked_until <= ?", (_now(),))
        conn.commit()


def list_blocked():
    """Lista IP-urilor inca blocate, cel mai recent blocat primul."""
    conn = _require_conn()
    rows = conn.execute(
        """
        SELECT ip, blocked_until, reason, created_at
        FROM blocked_ips
        WHERE blocked_until > ?
        ORDER BY created_at DESC
        """,
        (_now(),),
    ).fetchall()
    return _rows_to_dicts(rows)
