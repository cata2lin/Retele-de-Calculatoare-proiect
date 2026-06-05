"""Proxy de securitate: analizeaza fiecare cerere HTTP si o transmite mai departe catre aplicatia reala."""

import asyncio
import time
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

import config
import baza_date
import model_llm
import reguli
from panou import register_dashboard
from caracteristici import FeatureExtractor
from model_anomalii import get_detector
from jurnal import RequestLogger


# === Stare globala a aplicatiei (initializata la pornire) ===
extractor = None
logger = None
detector = None
http_client = None
# Retinem o singura data daca Ollama e disponibil, ca sa nu il interogam la fiecare cerere.
llm_available = False


# Anteturile "hop-by-hop" nu se transmit mai departe: descriu conexiunea TCP curenta,
# nu continutul raspunsului. Le eliminam si din cererea spre backend si din raspunsul lui.
HOP_BY_HOP_HEADERS = {
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "upgrade",
}

# Prioritatea categoriilor cand alegem una singura de afisat (cea mai grava prima).
CATEGORY_PRIORITY = [
    config.CAT_INJECTION,
    config.CAT_PATH_TRAVERSAL,
    config.CAT_BRUTE_FORCE,
    config.CAT_VULN_PROBE,
    config.CAT_SCANNER,
    config.CAT_SENSITIVE_FILE,
    config.CAT_DOS,
    config.CAT_SCRAPER,
    config.CAT_ANOMALY,
    config.CAT_NORMAL,
]

# Intentie probabila in functie de categoria dominanta (folosita cand LLM-ul nu da una).
INTENT_BY_CATEGORY = {
    config.CAT_NORMAL: "Acces obisnuit la aplicatie.",
    config.CAT_SCRAPER: "Colectare automata de continut (scraping).",
    config.CAT_VULN_PROBE: "Cautare de cai si fisiere vulnerabile.",
    config.CAT_SCANNER: "Scanare automata cu o unealta specializata.",
    config.CAT_INJECTION: "Incercare de injectare de cod sau interogari.",
    config.CAT_BRUTE_FORCE: "Incercari repetate de ghicire a credentialelor.",
    config.CAT_PATH_TRAVERSAL: "Incercare de iesire din directorul aplicatiei.",
    config.CAT_DOS: "Trafic excesiv ce poate semana cu un atac de tip DoS.",
    config.CAT_ANOMALY: "Comportament neobisnuit fata de tiparul normal.",
    config.CAT_SENSITIVE_FILE: "Cautare de fisiere de configurare sensibile.",
}

# Actiune recomandata implicita pentru fiecare categorie (cand LLM-ul nu propune una).
ACTION_BY_CATEGORY = {
    config.CAT_NORMAL: "Nicio actiune, trafic normal.",
    config.CAT_SCRAPER: "Limitare a ratei de cereri pentru acest IP.",
    config.CAT_VULN_PROBE: "Monitorizare atenta si verificarea cailor expuse.",
    config.CAT_SCANNER: "Blocarea temporara a IP-ului si analiza logurilor.",
    config.CAT_INJECTION: "Blocare imediata si verificarea validarii intrarilor.",
    config.CAT_BRUTE_FORCE: "Blocarea IP-ului si activarea limitarii la autentificare.",
    config.CAT_PATH_TRAVERSAL: "Blocare si verificarea regulilor de acces la fisiere.",
    config.CAT_DOS: "Limitarea ratei sau blocarea temporara a IP-ului.",
    config.CAT_ANOMALY: "Monitorizare suplimentara a acestui IP.",
    config.CAT_SENSITIVE_FILE: "Blocare si ascunderea fisierelor sensibile de la accesul public.",
}


def combine_scores(rule_score, anomaly_score, llm_score, llm_used):
    """Combina scorurile partiale intr-un scor final 0..100, cu podea pentru regulile clare."""
    if llm_used:
        final = 0.40 * rule_score + 0.25 * anomaly_score + 0.35 * llm_score
    else:
        final = 0.60 * rule_score + 0.40 * anomaly_score

    # O regula clara (scor mare) nu trebuie diluata de scoruri mici la celelalte componente.
    if rule_score >= 80:
        final = max(final, 80)

    final = int(round(final))
    return max(0, min(100, final))


def _pick_top_category(categories):
    """Alege categoria dominanta dupa prioritatea predefinita."""
    for cat in CATEGORY_PRIORITY:
        if cat in categories:
            return cat
    # Daca lista contine ceva neprevazut, intoarcem primul element; altfel normal.
    return categories[0] if categories else config.CAT_NORMAL


def build_decision(rule_result, anomaly_result, llm_result, final_score):
    """Construieste verdictul final: categorii, categorie dominanta, motiv, intentie si actiune."""
    # Pornim de la categoriile gasite de reguli si adaugam ce semnaleaza anomalia/LLM-ul.
    categories = list(rule_result.get("categories", []))

    if anomaly_result.get("is_anomaly") and config.CAT_ANOMALY not in categories:
        categories.append(config.CAT_ANOMALY)

    if llm_result and llm_result.get("is_suspicious"):
        llm_cat = llm_result.get("category", config.CAT_ANOMALY)
        if llm_cat and llm_cat != config.CAT_NORMAL and llm_cat not in categories:
            categories.append(llm_cat)

    # Daca nimic nu a fost semnalat, cererea e considerata normala.
    if not categories:
        categories = [config.CAT_NORMAL]

    top_category = _pick_top_category(categories)

    # Concatenam motivele din toate sursele care au ceva relevant de spus.
    reasons = list(rule_result.get("reasons", []))
    if anomaly_result.get("is_anomaly"):
        anom_reason = anomaly_result.get("reason")
        if anom_reason:
            reasons.append(anom_reason)
    if llm_result and llm_result.get("reason"):
        reasons.append("LLM: " + llm_result["reason"])

    if reasons:
        reason = "; ".join(reasons)
    else:
        reason = "Cerere fara semnale de risc."

    # Intentia si actiunea vin de la LLM daca exista, altfel le derivam din categoria dominanta.
    if llm_result and llm_result.get("possible_intent"):
        possible_intent = llm_result["possible_intent"]
    else:
        possible_intent = INTENT_BY_CATEGORY.get(top_category, "Intentie necunoscuta.")

    if llm_result and llm_result.get("recommended_action"):
        recommended_action = llm_result["recommended_action"]
    else:
        verdict_now = config.verdict_for_score(final_score)
        base_action = ACTION_BY_CATEGORY.get(top_category, "Monitorizare suplimentara.")
        if verdict_now == "critic":
            recommended_action = "Blocare imediata recomandata. " + base_action
        elif verdict_now == "risc_ridicat":
            recommended_action = "Atentie sporita. " + base_action
        else:
            recommended_action = base_action

    return {
        "categories": categories,
        "top_category": top_category,
        "verdict": config.verdict_for_score(final_score),
        "final_score": final_score,
        "reason": reason,
        "possible_intent": possible_intent,
        "recommended_action": recommended_action,
    }


@asynccontextmanager
async def lifespan(app):
    """Pregateste resursele la pornire si le elibereaza la oprire."""
    global extractor, logger, detector, http_client, llm_available

    config.ensure_dirs()
    baza_date.init_db()

    # Detectorul de anomalii se incarca de pe disc (sau se antreneaza daca lipseste).
    detector = get_detector()

    # Verificam o singura data daca LLM-ul local raspunde; daca nu, lucram fara el.
    llm_available = model_llm.is_available()
    if llm_available:
        print("Ollama este disponibil; LLM-ul va fi folosit pentru cazurile suspecte.")
    else:
        print("Ollama indisponibil; analiza continua doar cu reguli si model de anomalii.")

    extractor = FeatureExtractor()
    logger = RequestLogger()
    http_client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)

    print("Proxy-ul de securitate asculta pe portul", config.PROXY_PORT)
    print("Cererile sunt transmise catre", config.BACKEND_URL)
    print("Panoul de monitorizare: http://127.0.0.1:%d/dashboard" % config.PROXY_PORT)

    try:
        yield
    finally:
        if http_client is not None:
            await http_client.aclose()


app = FastAPI(lifespan=lifespan)

# Inregistram panoul INAINTE de ruta catch-all, ca rutele /dashboard sa aiba prioritate.
register_dashboard(app)


def _client_ip(request):
    """Determina IP-ul real al clientului (primul din x-forwarded-for sau IP-ul conexiunii)."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    if request.client and request.client.host:
        return request.client.host
    return "necunoscut"


def _build_meta(request, ip, body):
    """Construieste dictionarul meta al cererii conform contractului comun."""
    headers = {k.lower(): v for k, v in request.headers.items()}
    return {
        "ip": ip,
        "method": request.method,
        "path": request.url.path,
        "query": request.url.query,
        "headers": headers,
        "user_agent": headers.get("user-agent", ""),
        "body": body,
        "body_size": len(body),
    }


def _forward_headers(meta):
    """Pregateste anteturile pentru backend: copiem tot, mai putin host si cele hop-by-hop."""
    out = {}
    for k, v in meta["headers"].items():
        if k == "host" or k in HOP_BY_HOP_HEADERS:
            continue
        out[k] = v
    return out


def _response_headers(backend_headers):
    """Pastreaza anteturile raspunsului backend-ului, fara cele hop-by-hop."""
    out = {}
    for k, v in backend_headers.items():
        if k.lower() in HOP_BY_HOP_HEADERS:
            continue
        out[k] = v
    return out


@app.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
async def proxy(request: Request, full_path: str):
    """Analizeaza cererea, decide scorul de risc si o transmite mai departe la backend."""
    ip = _client_ip(request)

    # Citim corpul O SINGURA DATA si il refolosim peste tot (analiza + transmitere).
    body = await request.body()
    meta = _build_meta(request, ip, body)

    # === Analiza: caracteristici comportamentale + reguli + model de anomalii ===
    features = extractor.extract(ip, meta)
    rule_result = reguli.evaluate(meta, features)
    anomaly_result = detector.score(features)

    rule_score = rule_result["rule_score"]
    anomaly_score = anomaly_result["anomaly_score"]

    # Scorul preliminar (fara LLM) decide daca merita sa deranjam modelul lent.
    preliminary = combine_scores(rule_score, anomaly_score, 0, False)

    llm_result = None
    if preliminary >= config.LLM_TRIGGER_SCORE and llm_available:
        payload = {
            "ip": ip,
            "method": meta["method"],
            "path": meta["path"],
            "query": meta["query"],
            "user_agent": meta["user_agent"],
            "status": "necunoscut",
        }
        # Apelul catre LLM e sincron (requests); il ducem pe alt thread ca sa nu blocam bucla async.
        llm_result = await asyncio.to_thread(model_llm.classify, payload)

    llm_score = llm_result["risk_score"] if llm_result else 0
    final_score = combine_scores(
        rule_score, anomaly_score, llm_score, llm_result is not None
    )

    decision = build_decision(rule_result, anomaly_result, llm_result, final_score)

    # === Verificam daca IP-ul e deja blocat (curatam intai blocarile expirate) ===
    baza_date.unblock_expired()
    if baza_date.is_blocked(ip):
        status_code = 403
        response_size = 0
        # Cererea e respinsa fara a ajunge la backend; o inregistram totusi.
        # Un 403 pe o cale de login conteaza ca esec de autentificare.
        is_failed_login = (
            status_code in (401, 403)
            or (meta["path"] in config.LOGIN_PATHS and status_code >= 400)
        )
        extractor.record_event(
            ip, meta["path"], status_code, 0.0, response_size, is_failed_login
        )
        logger.log_request(
            meta=meta,
            features=features,
            rule_result=rule_result,
            anomaly_result=anomaly_result,
            llm_result=llm_result,
            decision=decision,
            status_code=status_code,
            latency_ms=0.0,
            response_size=response_size,
            blocked=True,
        )
        return JSONResponse(
            status_code=403,
            content={
                "eroare": "Acces blocat",
                "mesaj": "IP-ul tau este blocat temporar din cauza activitatii suspecte.",
                "scor": final_score,
            },
        )

    # === Transmitem cererea la backend si masuram latenta ===
    forward_headers = _forward_headers(meta)
    target_url = config.BACKEND_URL + meta["path"]

    start = time.perf_counter()
    try:
        backend_resp = await http_client.request(
            meta["method"],
            target_url,
            params=meta["query"],
            content=body,
            headers=forward_headers,
        )
    except httpx.HTTPError as exc:
        # Backend-ul nu raspunde (oprit, timeout, conexiune refuzata): intoarcem 502.
        latency_ms = (time.perf_counter() - start) * 1000.0
        status_code = 502
        response_size = 0

        is_failed_login = (
            status_code in (401, 403)
            or (meta["path"] in config.LOGIN_PATHS and status_code >= 400)
        )
        extractor.record_event(
            ip, meta["path"], status_code, latency_ms, response_size, is_failed_login
        )
        logger.log_request(
            meta=meta,
            features=features,
            rule_result=rule_result,
            anomaly_result=anomaly_result,
            llm_result=llm_result,
            decision=decision,
            status_code=status_code,
            latency_ms=latency_ms,
            response_size=response_size,
            blocked=False,
        )
        print("Eroare la contactarea backend-ului:", exc)
        return JSONResponse(
            status_code=502,
            content={
                "eroare": "Backend indisponibil",
                "mesaj": "Aplicatia din spatele proxy-ului nu a putut fi contactata.",
            },
        )

    latency_ms = (time.perf_counter() - start) * 1000.0
    content = backend_resp.content
    status_code = backend_resp.status_code
    response_size = len(content)

    # === Blocare automata daca scorul depaseste pragul configurat ===
    blocked = False
    if config.AUTO_BLOCK and final_score >= config.AUTO_BLOCK_SCORE:
        motiv = "Scor de risc %d (%s)" % (final_score, decision["top_category"])
        baza_date.block_ip(ip, config.BLOCK_MINUTES, motiv)
        blocked = True

    # Esec de autentificare: status 401/403, sau cale de login cu raspuns de eroare.
    is_failed_login = (
        status_code in (401, 403)
        or (meta["path"] in config.LOGIN_PATHS and status_code >= 400)
    )

    # Inregistram evenimentul incheiat pentru ferestrele comportamentale viitoare.
    extractor.record_event(
        ip, meta["path"], status_code, latency_ms, response_size, is_failed_login
    )

    logger.log_request(
        meta=meta,
        features=features,
        rule_result=rule_result,
        anomaly_result=anomaly_result,
        llm_result=llm_result,
        decision=decision,
        status_code=status_code,
        latency_ms=latency_ms,
        response_size=response_size,
        blocked=blocked,
    )

    # Construim raspunsul catre client din raspunsul backend-ului, fara anteturi hop-by-hop.
    return Response(
        content=content,
        status_code=status_code,
        headers=_response_headers(backend_resp.headers),
        media_type=backend_resp.headers.get("content-type"),
    )


if __name__ == "__main__":
    import uvicorn

    config.ensure_dirs()
    uvicorn.run(app, host=config.PROXY_HOST, port=config.PROXY_PORT)
