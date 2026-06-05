"""Panou web de monitorizare: pagina HTML si endpoint-uri JSON pentru date live."""

import json

from fastapi.responses import HTMLResponse, JSONResponse

import config
import baza_date


def register_dashboard(app):
    """Inregistreaza rutele panoului pe aplicatia FastAPI primita."""

    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard_page():
        return HTMLResponse(content=dashboard_html())

    @app.get("/dashboard/api/stats")
    def api_stats():
        return JSONResponse(
            {
                "summary": baza_date.stats_summary(),
                "categories": baza_date.category_counts(),
                "verdicts": baza_date.verdict_counts(),
            }
        )

    @app.get("/dashboard/api/requests")
    def api_requests(limit: int = 100, min_score: int = 0):
        # Limitam valorile primite de la client ca sa nu cerem mii de randuri din greseala.
        if limit < 1:
            limit = 1
        if limit > 1000:
            limit = 1000
        if min_score < 0:
            min_score = 0
        if min_score > 100:
            min_score = 100
        return JSONResponse(baza_date.recent_requests(limit=limit, min_score=min_score))

    @app.get("/dashboard/api/ips")
    def api_ips():
        return JSONResponse(baza_date.top_ips(20))

    @app.get("/dashboard/api/blocked")
    def api_blocked():
        return JSONResponse(baza_date.list_blocked())


def dashboard_html():
    """Construieste pagina completa a panoului (HTML + CSS + JS inline, fara CDN)."""

    # Etichete prietenoase in romana, trimise in JS.
    category_labels = {
        config.CAT_NORMAL: "Cerere normala",
        config.CAT_SCRAPER: "Scraper",
        config.CAT_VULN_PROBE: "Sondare vulnerabilitati",
        config.CAT_SCANNER: "Scaner",
        config.CAT_INJECTION: "Incercare de injectie",
        config.CAT_BRUTE_FORCE: "Brute force",
        config.CAT_PATH_TRAVERSAL: "Traversare de directoare",
        config.CAT_DOS: "Comportament de tip DoS",
        config.CAT_ANOMALY: "Anomalie necunoscuta",
        config.CAT_SENSITIVE_FILE: "Sondare fisier sensibil",
    }
    labels_json = json.dumps(category_labels)

    verdict_labels = {
        "normal": "Normal",
        "suspect": "Suspect",
        "risc_ridicat": "Risc ridicat",
        "critic": "Critic",
    }
    verdict_json = json.dumps(verdict_labels)

    return PAGE \
        .replace("__PROXY_PORT__", str(config.PROXY_PORT)) \
        .replace("__LABELS_JSON__", labels_json) \
        .replace("__VERDICT_JSON__", verdict_json) \
        .replace("__NORMAL_MAX__", str(config.RISK_NORMAL_MAX)) \
        .replace("__SUSPECT_MAX__", str(config.RISK_SUSPECT_MAX)) \
        .replace("__HIGH_MAX__", str(config.RISK_HIGH_MAX))


# Pagina e tinuta intr-o constanta separata ca sa nu amestecam HTML-ul cu logica.
PAGE = """<!DOCTYPE html>
<html lang="ro">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Consola de monitorizare - Analizor trafic HTTP</title>
<style>
  :root {
    --bg: #0f1217;
    --bg2: #141922;
    --panel: #161c26;
    --panel-2: #1b2330;
    --border: #232c3a;
    --text: #dde3ec;
    --muted: #8893a4;
    --accent: #e2a23b;
    --accent-2: #5aa7d6;
    --c-normal: #46b25e;
    --c-suspect: #d8a52a;
    --c-high: #e0822f;
    --c-crit: #e15041;
  }
  * { box-sizing: border-box; }
  html, body { height: 100%; }
  body {
    margin: 0;
    font-family: "Segoe UI", system-ui, Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    font-size: 14px;
    line-height: 1.45;
  }
  .mono { font-family: Consolas, "SF Mono", "DejaVu Sans Mono", monospace; }

  /* Bara de sus */
  .topbar {
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 12px 22px;
    background: var(--bg2);
    border-bottom: 2px solid var(--accent);
  }
  .mark {
    width: 38px; height: 38px;
    flex: 0 0 38px;
    display: grid; place-items: center;
    background: var(--accent);
    color: #1a1205;
    font-weight: 800;
    font-family: Consolas, monospace;
    letter-spacing: -1px;
    border-radius: 5px;
  }
  .titles h1 { margin: 0; font-size: 17px; font-weight: 600; letter-spacing: 0.2px; }
  .titles p { margin: 2px 0 0; font-size: 12px; color: var(--muted); }
  .status {
    margin-left: auto;
    display: flex; align-items: center; gap: 8px;
    font-size: 12px; color: var(--muted);
  }
  .dot {
    width: 9px; height: 9px; border-radius: 50%;
    background: var(--c-normal);
    box-shadow: 0 0 0 0 rgba(70,178,94,0.6);
    animation: pulse 2.2s infinite;
  }
  @keyframes pulse {
    0% { box-shadow: 0 0 0 0 rgba(70,178,94,0.5); }
    70% { box-shadow: 0 0 0 7px rgba(70,178,94,0); }
    100% { box-shadow: 0 0 0 0 rgba(70,178,94,0); }
  }

  .page { padding: 20px 22px 40px; max-width: 1320px; margin: 0 auto; }

  /* Cartonase statistici */
  .tiles {
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 12px;
    margin-bottom: 18px;
  }
  @media (max-width: 1080px) { .tiles { grid-template-columns: repeat(3, 1fr); } }
  @media (max-width: 560px) { .tiles { grid-template-columns: repeat(2, 1fr); } }
  .tile {
    background: var(--panel);
    border: 1px solid var(--border);
    border-top: 3px solid var(--muted);
    border-radius: 6px;
    padding: 12px 14px;
  }
  .tile .n { font-family: Consolas, monospace; font-size: 26px; font-weight: 700; }
  .tile .l { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.6px; margin-top: 3px; }
  .tile.t-total { border-top-color: var(--accent-2); }
  .tile.t-susp  { border-top-color: var(--c-suspect); }
  .tile.t-high  { border-top-color: var(--c-high); }
  .tile.t-crit  { border-top-color: var(--c-crit); }
  .tile.t-block { border-top-color: var(--muted); }
  .tile.t-anom  { border-top-color: var(--accent); }

  /* Legenda nivelurilor de risc */
  .legend {
    display: flex; flex-wrap: wrap; gap: 16px;
    padding: 9px 14px; margin-bottom: 18px;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 6px;
    font-size: 12px; color: var(--muted);
  }
  .legend span { display: inline-flex; align-items: center; gap: 7px; }
  .sw { width: 11px; height: 11px; border-radius: 2px; display: inline-block; }

  .grid2 { display: grid; grid-template-columns: 1fr 1.3fr; gap: 16px; margin-bottom: 18px; }
  @media (max-width: 940px) { .grid2 { grid-template-columns: 1fr; } }

  .panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
  }
  .panel > h2 {
    margin: 0;
    padding: 11px 16px;
    font-size: 13px; font-weight: 600;
    letter-spacing: 0.3px;
    border-bottom: 1px solid var(--border);
    background: var(--panel-2);
  }
  .panel .body { padding: 12px 16px; }

  /* Bare categorii */
  .cat { margin-bottom: 11px; }
  .cat:last-child { margin-bottom: 0; }
  .cat .top { display: flex; justify-content: space-between; font-size: 13px; margin-bottom: 4px; }
  .cat .top .ct { font-family: Consolas, monospace; color: var(--accent); font-weight: 700; }
  .cat .track { height: 7px; background: var(--bg); border-radius: 4px; overflow: hidden; }
  .cat .fill { height: 100%; background: linear-gradient(90deg, var(--accent-2), var(--accent)); }

  /* Tabele */
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 8px 16px; border-bottom: 1px solid var(--border); }
  th { font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--muted); font-weight: 600; }
  tbody tr:last-child td { border-bottom: none; }
  tbody tr:hover { background: var(--panel-2); }
  td.num, th.num { text-align: right; }
  td.ip, td.path { font-family: Consolas, monospace; font-size: 12.5px; }
  td.path { color: var(--accent-2); word-break: break-all; max-width: 360px; }
  td.reason { color: var(--muted); font-size: 12.5px; max-width: 340px; }

  .score {
    display: inline-block; min-width: 30px;
    padding: 1px 8px; border-radius: 4px;
    font-family: Consolas, monospace; font-weight: 700; color: #11140f;
    text-align: center;
  }
  .badge {
    display: inline-block; padding: 1px 9px; border-radius: 4px;
    font-size: 12px; font-weight: 600; white-space: nowrap;
    border: 1px solid transparent;
  }
  .b-normal { color: var(--c-normal); background: rgba(70,178,94,0.12); border-color: rgba(70,178,94,0.35); }
  .b-suspect { color: var(--c-suspect); background: rgba(216,165,42,0.12); border-color: rgba(216,165,42,0.35); }
  .b-risc_ridicat { color: var(--c-high); background: rgba(224,130,47,0.12); border-color: rgba(224,130,47,0.35); }
  .b-critic { color: var(--c-crit); background: rgba(225,80,65,0.14); border-color: rgba(225,80,65,0.4); }

  .controls { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; padding: 11px 16px; border-bottom: 1px solid var(--border); }
  .controls label { font-size: 12px; color: var(--muted); }
  .controls input {
    width: 84px; padding: 5px 8px;
    background: var(--bg); color: var(--text);
    border: 1px solid var(--border); border-radius: 4px;
    font-family: Consolas, monospace;
  }
  .controls .count { margin-left: auto; font-size: 12px; color: var(--muted); }

  .empty { padding: 16px; color: var(--muted); font-size: 13px; }

  footer { padding: 14px 22px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--border); text-align: center; }
</style>
</head>
<body>

<div class="topbar">
  <div class="mark">AT</div>
  <div class="titles">
    <h1>Analizor de trafic HTTP</h1>
    <p>Consola de monitorizare a securitatii &middot; proxy pe portul __PROXY_PORT__</p>
  </div>
  <div class="status">
    <span class="dot"></span>
    <span id="updated">se conecteaza...</span>
  </div>
</div>

<div class="page">

  <div class="tiles">
    <div class="tile t-total"><div class="n" id="c-total">-</div><div class="l">Total cereri</div></div>
    <div class="tile t-susp"><div class="n" id="c-suspecte">-</div><div class="l">Suspecte</div></div>
    <div class="tile t-high"><div class="n" id="c-risc">-</div><div class="l">Risc ridicat</div></div>
    <div class="tile t-crit"><div class="n" id="c-critice">-</div><div class="l">Critice</div></div>
    <div class="tile t-block"><div class="n" id="c-blocate">-</div><div class="l">IP-uri blocate</div></div>
    <div class="tile t-anom"><div class="n" id="c-anomalii">-</div><div class="l">Anomalii</div></div>
  </div>

  <div class="legend">
    <span><i class="sw" style="background:var(--c-normal)"></i> Normal (0-__NORMAL_MAX__)</span>
    <span><i class="sw" style="background:var(--c-suspect)"></i> Suspect (__NORMAL_PLUS__-__SUSPECT_MAX__)</span>
    <span><i class="sw" style="background:var(--c-high)"></i> Risc ridicat (__SUSPECT_PLUS__-__HIGH_MAX__)</span>
    <span><i class="sw" style="background:var(--c-crit)"></i> Critic (__HIGH_PLUS__-100)</span>
  </div>

  <div class="grid2">
    <div class="panel">
      <h2>Distributie pe categorii</h2>
      <div class="body">
        <div id="categories"></div>
        <div class="empty" id="categories-empty" style="display:none;">Nicio cerere suspecta inregistrata inca.</div>
      </div>
    </div>

    <div class="panel">
      <h2>IP-uri urmarite</h2>
      <table>
        <thead>
          <tr><th>IP</th><th class="num">Cereri</th><th class="num">Scor max</th><th class="num">Mediu</th><th>Categorii</th><th>Ultima activitate</th></tr>
        </thead>
        <tbody id="ips"></tbody>
      </table>
      <div class="empty" id="ips-empty" style="display:none;">Niciun IP cu scor relevant.</div>
    </div>
  </div>

  <div class="panel">
    <h2>Cereri recente</h2>
    <div class="controls">
      <label for="min-score">Scor minim</label>
      <input type="number" id="min-score" min="0" max="100" value="0">
      <label for="limit">Limita</label>
      <input type="number" id="limit" min="1" max="1000" value="100">
      <span class="count" id="req-count"></span>
    </div>
    <table>
      <thead>
        <tr>
          <th>Ora</th><th>IP</th><th>Metoda</th><th>Cale</th><th class="num">Status</th>
          <th class="num">Scor</th><th>Verdict</th><th>Categorie</th><th>Motiv</th>
        </tr>
      </thead>
      <tbody id="requests"></tbody>
    </table>
    <div class="empty" id="requests-empty" style="display:none;">Nicio cerere care sa corespunda filtrului.</div>
  </div>

</div>

<footer>
  Proiect la disciplina Retele de Calculatoare &middot; reimprospatare automata la 5 secunde &middot;
  detectia LLM (Ollama) este optionala
</footer>

<script>
"use strict";

var CATEGORY_LABELS = __LABELS_JSON__;
var VERDICT_LABELS = __VERDICT_JSON__;

// Afisam mereu datele ca text scapat, ca sa nu fie posibila injectia de HTML din cai/user-agent/motive.
function esc(value) {
  if (value === null || value === undefined) { return ""; }
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function scoreColor(score) {
  var s = Number(score) || 0;
  if (s <= __NORMAL_MAX__) { return "var(--c-normal)"; }
  if (s <= __SUSPECT_MAX__) { return "var(--c-suspect)"; }
  if (s <= __HIGH_MAX__) { return "var(--c-high)"; }
  return "var(--c-crit)";
}

function verdictLabel(v) { return VERDICT_LABELS[v] || (v ? v : "-"); }
function categoryLabel(c) { return CATEGORY_LABELS[c] || (c ? c : "-"); }

function shortTime(ts) {
  if (!ts) { return "-"; }
  var parts = String(ts).split("T");
  if (parts.length === 2) { return parts[0].slice(5) + " " + parts[1]; }
  return ts;
}

async function loadStats() {
  var res = await fetch("/dashboard/api/stats");
  var data = await res.json();
  var s = data.summary || {};
  document.getElementById("c-total").textContent = s.total || 0;
  document.getElementById("c-suspecte").textContent = s.suspecte || 0;
  document.getElementById("c-risc").textContent = s.risc_ridicat || 0;
  document.getElementById("c-critice").textContent = s.critice || 0;
  document.getElementById("c-blocate").textContent = s.blocate || 0;
  document.getElementById("c-anomalii").textContent = s.anomalii || 0;
  renderCategories(data.categories || []);
}

function renderCategories(cats) {
  var box = document.getElementById("categories");
  var empty = document.getElementById("categories-empty");
  box.innerHTML = "";
  if (!cats.length) { empty.style.display = "block"; return; }
  empty.style.display = "none";

  var max = 0;
  for (var i = 0; i < cats.length; i++) { if (cats[i].count > max) { max = cats[i].count; } }
  if (max < 1) { max = 1; }

  for (var j = 0; j < cats.length; j++) {
    var c = cats[j];
    var pct = Math.round((Number(c.count) / max) * 100);
    var el = document.createElement("div");
    el.className = "cat";
    el.innerHTML =
      '<div class="top"><span>' + esc(categoryLabel(c.category)) +
      '</span><span class="ct">' + esc(c.count) + '</span></div>' +
      '<div class="track"><div class="fill" style="width:' + pct + '%"></div></div>';
    box.appendChild(el);
  }
}

async function loadIps() {
  var res = await fetch("/dashboard/api/ips");
  var rows = await res.json();
  var body = document.getElementById("ips");
  var empty = document.getElementById("ips-empty");
  body.innerHTML = "";
  if (!rows.length) { empty.style.display = "block"; return; }
  empty.style.display = "none";

  for (var i = 0; i < rows.length; i++) {
    var r = rows[i];
    var maxScore = Number(r.max_score) || 0;
    var tr = document.createElement("tr");
    tr.innerHTML =
      '<td class="ip">' + esc(r.ip) + "</td>" +
      '<td class="num">' + esc(r.total) + "</td>" +
      '<td class="num"><span class="score" style="background:' + scoreColor(maxScore) + '">' + esc(maxScore) + "</span></td>" +
      '<td class="num">' + esc(r.avg_score) + "</td>" +
      "<td>" + esc(r.categories || "-") + "</td>" +
      "<td>" + esc(shortTime(r.last_seen)) + "</td>";
    body.appendChild(tr);
  }
}

async function loadRequests() {
  var minScore = parseInt(document.getElementById("min-score").value, 10);
  var limit = parseInt(document.getElementById("limit").value, 10);
  if (isNaN(minScore) || minScore < 0) { minScore = 0; }
  if (isNaN(limit) || limit < 1) { limit = 100; }

  var res = await fetch("/dashboard/api/requests?limit=" + limit + "&min_score=" + minScore);
  var rows = await res.json();
  var body = document.getElementById("requests");
  var empty = document.getElementById("requests-empty");
  body.innerHTML = "";
  document.getElementById("req-count").textContent = rows.length + " cereri afisate";
  if (!rows.length) { empty.style.display = "block"; return; }
  empty.style.display = "none";

  for (var i = 0; i < rows.length; i++) {
    var r = rows[i];
    var score = Number(r.final_score) || 0;
    var verdict = r.verdict || "normal";
    var fullPath = r.path || "/";
    if (r.query) { fullPath += "?" + r.query; }

    var tr = document.createElement("tr");
    tr.innerHTML =
      "<td>" + esc(shortTime(r.timestamp)) + "</td>" +
      '<td class="ip">' + esc(r.ip) + "</td>" +
      "<td>" + esc(r.method) + "</td>" +
      '<td class="path">' + esc(fullPath) + "</td>" +
      '<td class="num">' + esc(r.status_code) + "</td>" +
      '<td class="num"><span class="score" style="background:' + scoreColor(score) + '">' + esc(score) + "</span></td>" +
      '<td><span class="badge b-' + esc(verdict) + '">' + esc(verdictLabel(verdict)) + "</span></td>" +
      "<td>" + esc(categoryLabel(r.top_category)) + "</td>" +
      '<td class="reason">' + esc(r.reason || "-") + "</td>";
    body.appendChild(tr);
  }
}

async function refreshAll() {
  try {
    await Promise.all([loadStats(), loadIps(), loadRequests()]);
    var now = new Date();
    document.getElementById("updated").textContent = "actualizat la " + now.toLocaleTimeString("ro-RO");
  } catch (err) {
    document.getElementById("updated").textContent = "eroare la incarcarea datelor";
  }
}

document.getElementById("min-score").addEventListener("change", loadRequests);
document.getElementById("limit").addEventListener("change", loadRequests);

refreshAll();
setInterval(refreshAll, 5000);
</script>
</body>
</html>
"""

# Pragurile +1 pentru afisarea intervalelor din legenda.
PAGE = PAGE \
    .replace("__NORMAL_PLUS__", str(config.RISK_NORMAL_MAX + 1)) \
    .replace("__SUSPECT_PLUS__", str(config.RISK_SUSPECT_MAX + 1)) \
    .replace("__HIGH_PLUS__", str(config.RISK_HIGH_MAX + 1))
