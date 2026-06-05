"""Configurare centralizata a analizorului de trafic HTTP (constante si cai)."""

import os
from pathlib import Path

# === Constante de retea ===
PROXY_HOST = "0.0.0.0"
PROXY_PORT = 8000
BACKEND_URL = "http://127.0.0.1:8001"

# === Cai (toate relative la folderul acestui fisier) ===
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
LOGS_DIR = BASE_DIR / "logs"
REPORTS_DIR = BASE_DIR / "reports"

DB_PATH = DATA_DIR / "traffic.db"
ANOMALY_MODEL_PATH = MODELS_DIR / "anomaly.joblib"
LOG_FILE = LOGS_DIR / "traffic.log"

# === Setari Ollama (LLM local optional) ===
OLLAMA_URL = "http://127.0.0.1:11434"
# Modelul implicit e llama3.2 (mic, se descarca usor). Daca ai deja alt model in Ollama,
# il poti folosi fara sa modifici codul, prin variabila de mediu OLLAMA_MODEL.
# ex pe Windows:  set OLLAMA_MODEL=llama3.1:8b
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")
# Modelele mai mari raspund in cateva secunde; lasam timp suficient, dar tot marginit.
OLLAMA_TIMEOUT = 30.0
# Sub acest scor preliminar nu mai deranjam LLM-ul (e lent si scump)
LLM_TRIGGER_SCORE = 30

# === Fereastra de timp pentru caracteristici comportamentale ===
WINDOW_SECONDS = 60

# === Praguri de risc pentru verdict ===
RISK_NORMAL_MAX = 30
RISK_SUSPECT_MAX = 60
RISK_HIGH_MAX = 80


def verdict_for_score(score):
    """Transforma un scor 0..100 in verdict text."""
    if score <= RISK_NORMAL_MAX:
        return "normal"
    if score <= RISK_SUSPECT_MAX:
        return "suspect"
    if score <= RISK_HIGH_MAX:
        return "risc_ridicat"
    return "critic"


# === Blocare automata a IP-urilor periculoase ===
AUTO_BLOCK = True
AUTO_BLOCK_SCORE = 85
BLOCK_MINUTES = 10

# === Categorii de clasificare a cererilor ===
CAT_NORMAL = "normal_request"
CAT_SCRAPER = "scraper"
CAT_VULN_PROBE = "vulnerability_probe"
CAT_SCANNER = "scanner"
CAT_INJECTION = "injection_attempt"
CAT_BRUTE_FORCE = "brute_force"
CAT_PATH_TRAVERSAL = "path_traversal"
CAT_DOS = "dos_like_behavior"
CAT_ANOMALY = "unknown_anomaly"
CAT_SENSITIVE_FILE = "sensitive_file_probe"

ALL_CATEGORIES = [
    CAT_NORMAL,
    CAT_SCRAPER,
    CAT_VULN_PROBE,
    CAT_SCANNER,
    CAT_INJECTION,
    CAT_BRUTE_FORCE,
    CAT_PATH_TRAVERSAL,
    CAT_DOS,
    CAT_ANOMALY,
    CAT_SENSITIVE_FILE,
]

# === Cai sensibile cautate frecvent de scanere si boti ===
SENSITIVE_PATHS = [
    "/admin",
    "/administrator",
    "/login",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/.env",
    "/.git",
    "/.git/config",
    "/config",
    "/config.php",
    "/backup",
    "/backup.zip",
    "/db.sql",
    "/server-status",
    "/api/docs",
    "/actuator",
    "/actuator/health",
    "/xmlrpc.php",
    "/vendor/",
    "/storage/",
    "/.svn",
    "/web.config",
]

# Extensii de fisiere care nu ar trebui sa fie servite public
SENSITIVE_EXTENSIONS = [
    ".env",
    ".sql",
    ".bak",
    ".old",
    ".zip",
    ".tar",
    ".gz",
    ".pem",
    ".key",
    ".log",
    ".ini",
    ".config",
]

# === Fragmente de User-Agent specifice uneltelor de scanare (lowercase) ===
SUSPICIOUS_USER_AGENTS = [
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "dirbuster",
    "gobuster",
    "wpscan",
    "acunetix",
    "nessus",
    "curl",
    "wget",
    "python-requests",
    "python-urllib",
    "go-http-client",
    "httpclient",
    "scrapy",
    "java/",
    "libwww-perl",
    "zgrab",
]

# === Cai de autentificare (folosite pentru detectia de brute force) ===
LOGIN_PATHS = [
    "/login",
    "/api/login",
    "/auth",
    "/signin",
    "/wp-login.php",
]

# === Tipare REGEX pentru detectia atacurilor ===
# Sunt string-uri brute; modulele care le folosesc le compileaza cu re.IGNORECASE.

# Injectie SQL: ghilimea simpla, comentariu --, union/select, or/and N=N, drop/insert, sleep, benchmark
SQL_INJECTION_PATTERNS = [
    r"'",
    r"--",
    r"\bunion\b.{0,40}\bselect\b",
    r"\bselect\b.{0,80}\bfrom\b",
    r"\bor\b\s+\d+\s*=\s*\d+",
    r"\band\b\s+\d+\s*=\s*\d+",
    r"\bdrop\b\s+\btable\b",
    r"\binsert\b\s+\binto\b",
    r"\bsleep\s*\(\s*\d+",
    r"\bbenchmark\s*\(",
]

# Cross-site scripting: eticheta script, schema javascript:, handlere de evenimente, alert, document.cookie
XSS_PATTERNS = [
    r"<\s*script\b",
    r"javascript:",
    r"\bonerror\s*=",
    r"\bonload\s*=",
    r"\balert\s*\(",
    r"document\.cookie",
]

# Injectie de comenzi: separator ; sau | urmat de comenzi uzuale, plus substitutie de comanda
COMMAND_INJECTION_PATTERNS = [
    r"[;|]\s*(ls|cat|whoami|id|rm|wget|curl|nc|bash|sh)\b",
    r"\$\(.+\)",
    r"`[^`]+`",
]

# Traversare de directoare: ../ (si varianta encodata), ..\, fisiere de sistem cunoscute
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"(?:%2e){2}(?:%2f|/)",
    r"\.\.\\",
    r"/etc/passwd",
    r"/etc/shadow",
    r"\bwin\.ini\b",
    r"\bboot\.ini\b",
]

# === Ordinea exacta a caracteristicilor numerice pentru Isolation Forest ===
FEATURE_ORDER = [
    "requests_per_minute",
    "unique_paths_per_minute",
    "percentage_404",
    "average_response_size",
    "average_latency_ms",
    "user_agent_length",
    "number_of_query_parameters",
    "path_depth",
    "body_size",
    "failed_login_count",
]

# === Praguri folosite de motorul de reguli ===
RATE_SCRAPER_THRESHOLD = 40
RATE_DOS_THRESHOLD = 120
UNIQUE_PATHS_SCRAPER_THRESHOLD = 30
PERCENT_404_THRESHOLD = 0.4
FAILED_LOGIN_THRESHOLD = 8
LARGE_BODY_THRESHOLD = 1000000


def ensure_dirs():
    """Creeaza folderele necesare daca nu exista deja."""
    for d in (DATA_DIR, MODELS_DIR, LOGS_DIR, REPORTS_DIR):
        d.mkdir(parents=True, exist_ok=True)
