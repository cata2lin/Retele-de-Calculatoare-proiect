"""Motor de reguli rapide pentru clasificarea cererilor HTTP."""

import re
from urllib.parse import unquote

import config

# Compilam tiparele regex o singura data la incarcarea modulului, ca sa nu
# recompilam la fiecare cerere (proxy-ul evalueaza foarte des).
SQL_REGEX = [re.compile(p, re.IGNORECASE) for p in config.SQL_INJECTION_PATTERNS]
XSS_REGEX = [re.compile(p, re.IGNORECASE) for p in config.XSS_PATTERNS]
CMD_REGEX = [re.compile(p, re.IGNORECASE) for p in config.COMMAND_INJECTION_PATTERNS]
TRAVERSAL_REGEX = [re.compile(p, re.IGNORECASE) for p in config.PATH_TRAVERSAL_PATTERNS]

# User-agenti care tradeaza mai degraba un scraper/script decat o unealta de
# scanare agresiva; ii incadram la o categorie mai blanda.
SCRAPER_UA_HINTS = ["scrapy", "python-requests", "curl", "wget"]


def _any_match(regex_list, text):
    """Verifica daca vreun tipar din lista se potriveste in text."""
    if not text:
        return False
    for rx in regex_list:
        if rx.search(text):
            return True
    return False


def _short_ua(user_agent):
    """Scurteaza user-agent-ul pentru afisare in motive."""
    ua = user_agent.strip()
    if len(ua) > 40:
        return ua[:40] + "..."
    return ua


def evaluate(meta, features):
    """Aplica reguli rapide pe o cerere si intoarce scor, categorii si motive."""
    score = 0
    categories = []
    reasons = []

    path = meta.get("path", "") or ""
    query_raw = meta.get("query", "") or ""
    user_agent = meta.get("user_agent", "") or ""
    body = meta.get("body", b"") or b""

    # Decodam query-ul ca sa prindem tipare ascunse prin url-encoding.
    query_decoded = unquote(query_raw) if query_raw else ""

    # Corpul cererii il decodam best-effort doar daca exista ceva de decodat.
    if body:
        body_text = body.decode("utf-8", errors="ignore")
    else:
        body_text = ""

    path_lower = path.lower()

    # === Fisiere sensibile dupa extensie sau cale exacta ===
    sensitive_file_hit = False
    for ext in config.SENSITIVE_EXTENSIONS:
        if path_lower.endswith(ext):
            sensitive_file_hit = True
            break
    if not sensitive_file_hit:
        # Cai exacte de tip /.env, /.git, /.git/config etc.
        for sp in config.SENSITIVE_PATHS:
            spl = sp.lower()
            if spl.startswith("/.") and path_lower == spl:
                sensitive_file_hit = True
                break

    if sensitive_file_hit:
        score += 60
        categories.append(config.CAT_SENSITIVE_FILE)
        categories.append(config.CAT_VULN_PROBE)
        reasons.append("Cerere catre un fisier sensibil de configurare (%s)." % path)

    # === Cale administrativa/sensibila din SENSITIVE_PATHS ===
    admin_hit = False
    for sp in config.SENSITIVE_PATHS:
        spl = sp.lower()
        if spl.endswith("/"):
            # Pentru cai de tip /vendor/ verificam prefixul.
            if path_lower.startswith(spl):
                admin_hit = True
                break
        elif path_lower == spl or path_lower.startswith(spl + "/"):
            admin_hit = True
            break

    if admin_hit:
        score += 45
        categories.append(config.CAT_VULN_PROBE)
        categories.append(config.CAT_SCANNER)
        reasons.append("Acces la o cale administrativa/sensibila (%s)." % path)

    # === Injectii (SQL / XSS / comenzi) in query, path sau body ===
    targets = [query_decoded, path, body_text]

    if any(_any_match(SQL_REGEX, t) for t in targets):
        score += 70
        categories.append(config.CAT_INJECTION)
        reasons.append("Posibila injectie SQL detectata in cerere.")
    if any(_any_match(XSS_REGEX, t) for t in targets):
        score += 70
        categories.append(config.CAT_INJECTION)
        reasons.append("Posibil atac XSS detectat in cerere.")
    if any(_any_match(CMD_REGEX, t) for t in targets):
        score += 70
        categories.append(config.CAT_INJECTION)
        reasons.append("Posibila injectie de comenzi detectata in cerere.")

    # === Traversare de directoare in path sau query ===
    if _any_match(TRAVERSAL_REGEX, path) or _any_match(TRAVERSAL_REGEX, query_decoded):
        score += 65
        categories.append(config.CAT_PATH_TRAVERSAL)
        reasons.append("Posibila traversare de directoare (%s)." % path)

    # === User-agent ===
    ua_lower = user_agent.lower()
    if not user_agent.strip():
        score += 20
        categories.append(config.CAT_SCRAPER)
        reasons.append("Cerere fara user-agent.")
    else:
        for frag in config.SUSPICIOUS_USER_AGENTS:
            if frag in ua_lower:
                score += 25
                if any(h in frag for h in SCRAPER_UA_HINTS):
                    categories.append(config.CAT_SCRAPER)
                else:
                    categories.append(config.CAT_SCANNER)
                reasons.append("User-agent de unealta automata (%s)." % _short_ua(user_agent))
                break

    # === Rata de cereri pe minut ===
    rpm = features.get("requests_per_minute", 0)
    if rpm >= config.RATE_DOS_THRESHOLD:
        score += 55
        categories.append(config.CAT_DOS)
        reasons.append("Rata foarte mare de cereri (%d pe minut)." % int(rpm))
    elif rpm >= config.RATE_SCRAPER_THRESHOLD:
        score += 30
        categories.append(config.CAT_SCRAPER)
        reasons.append("Rata ridicata de cereri (%d pe minut)." % int(rpm))

    # === Numar mare de cai unice (comportament de crawling) ===
    unique_paths = features.get("unique_paths_per_minute", 0)
    if unique_paths >= config.UNIQUE_PATHS_SCRAPER_THRESHOLD:
        score += 30
        categories.append(config.CAT_SCRAPER)
        reasons.append("Multe cai diferite accesate (%d pe minut)." % int(unique_paths))

    # === Procent ridicat de 404 (cautare de resurse inexistente) ===
    pct_404 = features.get("percentage_404", 0)
    if pct_404 >= config.PERCENT_404_THRESHOLD and rpm >= 5:
        score += 35
        categories.append(config.CAT_VULN_PROBE)
        reasons.append("Procent ridicat de raspunsuri 404 (%d%%)." % int(round(pct_404 * 100)))

    # === Esecuri repetate de autentificare (brute force) ===
    failed_logins = features.get("failed_login_count", 0)
    if failed_logins >= config.FAILED_LOGIN_THRESHOLD:
        score += 50
        categories.append(config.CAT_BRUTE_FORCE)
        reasons.append("Esecuri repetate de autentificare (%d)." % int(failed_logins))

    # === Corp de cerere neobisnuit de mare ===
    body_size = features.get("body_size", 0)
    if body_size >= config.LARGE_BODY_THRESHOLD:
        score += 25
        categories.append(config.CAT_DOS)
        reasons.append("Corp de cerere neobisnuit de mare.")

    # Deduplicam categoriile pastrand ordinea de aparitie si scoatem categoria
    # normala (nu are sens sa o raportam ca motiv de risc).
    seen = set()
    final_categories = []
    for c in categories:
        if c == config.CAT_NORMAL:
            continue
        if c not in seen:
            seen.add(c)
            final_categories.append(c)

    rule_score = min(100, score)

    return {
        "rule_score": rule_score,
        "categories": final_categories,
        "reasons": reasons,
    }
