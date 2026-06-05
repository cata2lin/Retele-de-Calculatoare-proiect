"""Clasificator defensiv optional bazat pe un LLM local rulat prin Ollama."""

import json

import requests

import config


# Prompt de sistem defensiv: cere strict clasificare, nu instructiuni de atac
SYSTEM_PROMPT = (
    "Esti un clasificator defensiv de securitate web. Analizeaza cererea HTTP "
    "si decide daca e suspecta. Raspunde DOAR cu JSON valid cu cheile: "
    "is_suspicious (true/false), category, risk_score (0-100), reason, "
    "possible_intent, recommended_action. Nu da instructiuni de atac, doar "
    "clasifica si explica defensiv."
)


def is_available():
    """Verifica daca serverul Ollama raspunde pe /api/tags."""
    try:
        resp = requests.get(config.OLLAMA_URL + "/api/tags", timeout=2)
        return resp.status_code == 200
    except Exception:
        return False


def _clamp_score(value):
    """Transforma orice valoare intr-un intreg limitat la 0..100."""
    try:
        score = int(round(float(value)))
    except (TypeError, ValueError):
        return 50
    return max(0, min(100, score))


def _as_text(value, fallback):
    """Intoarce un string nevid; daca lipseste sau e gol, foloseste fallback-ul."""
    if value is None:
        return fallback
    text = str(value).strip()
    return text if text else fallback


def _build_prompt(payload):
    """Construieste promptul complet din partea defensiva plus cererea de analizat."""
    try:
        payload_text = json.dumps(payload, ensure_ascii=False)
    except (TypeError, ValueError):
        # Daca payload-ul nu e serializabil, il transformam brutal in text
        payload_text = str(payload)
    return SYSTEM_PROMPT + "\n\nCererea HTTP de analizat (JSON):\n" + payload_text


def classify(payload):
    """Cere LLM-ului local clasificarea unei cereri; intoarce dict sau None la eroare."""
    prompt = _build_prompt(payload)

    try:
        resp = requests.post(
            config.OLLAMA_URL + "/api/generate",
            json={
                "model": config.OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0},
            },
            timeout=config.OLLAMA_TIMEOUT,
        )
        if resp.status_code != 200:
            print("LLM: raspuns neasteptat de la Ollama, status", resp.status_code)
            return None

        data = resp.json()
        raw_response = data.get("response", "")
        parsed = json.loads(raw_response)
    except Exception as exc:
        # Orice problema (timeout, conexiune, JSON invalid) inseamna ca nu folosim LLM-ul
        print("LLM indisponibil sau raspuns invalid:", exc)
        return None

    if not isinstance(parsed, dict):
        print("LLM: raspunsul nu este un obiect JSON, il ignoram")
        return None

    # Validam si normalizam fiecare camp, ca sa respecte contractul comun
    category = _as_text(parsed.get("category"), config.CAT_ANOMALY)
    if category not in config.ALL_CATEGORIES:
        category = config.CAT_ANOMALY

    return {
        "is_suspicious": bool(parsed.get("is_suspicious", False)),
        "category": category,
        "risk_score": _clamp_score(parsed.get("risk_score", 50)),
        "reason": _as_text(parsed.get("reason"), "Fara explicatie de la model."),
        "possible_intent": _as_text(
            parsed.get("possible_intent"), "Intentie necunoscuta."
        ),
        "recommended_action": _as_text(
            parsed.get("recommended_action"), "Monitorizare suplimentara."
        ),
    }
