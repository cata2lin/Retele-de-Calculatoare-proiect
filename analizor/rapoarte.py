"""Generare de rapoarte (JSON, HTML, CSV) despre cererile flagate de analizorul de trafic."""

import csv
import html
import json
from datetime import datetime

import config
import baza_date


def _stamp():
    """Marca de timp pentru numele fisierelor: YYYYmmdd_HHMMSS."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _escape(value):
    """Pregateste o valoare pentru inserarea in HTML (scapa caracterele speciale)."""
    if value is None:
        return ""
    return html.escape(str(value))


def _parse_categories(raw):
    """Categoriile sunt salvate ca text JSON; le aducem inapoi la lista in mod tolerant."""
    if not raw:
        return []
    if isinstance(raw, list):
        return raw
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return parsed
        return [str(parsed)]
    except (ValueError, TypeError):
        # Daca din vreun motiv nu e JSON valid, pastram textul brut ca o singura categorie.
        return [str(raw)]


def _write_json(path, generated_at, summary, top_ips, flagged):
    """Scrie rezumatul structurat in format JSON."""
    payload = {
        "generat_la": generated_at,
        "rezumat": summary,
        "ip_uri_periculoase": top_ips,
        "numar_cereri_flagate": len(flagged),
        "cereri_flagate": flagged,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def _write_csv(path, flagged):
    """Scrie cererile flagate intr-un CSV lizibil (cu antet in romana)."""
    coloane = [
        ("timestamp", "Data"),
        ("ip", "IP"),
        ("method", "Metoda"),
        ("path", "Cale"),
        ("query", "Query"),
        ("status_code", "Status"),
        ("rule_score", "Scor reguli"),
        ("anomaly_score", "Scor anomalie"),
        ("llm_score", "Scor LLM"),
        ("final_score", "Scor final"),
        ("verdict", "Verdict"),
        ("top_category", "Categorie"),
        ("reason", "Motiv"),
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([antet for _, antet in coloane])
        for r in flagged:
            writer.writerow([r.get(cheie, "") for cheie, _ in coloane])


def _build_top_ips_table(top_ips):
    """Construieste randurile de tabel HTML pentru IP-urile periculoase."""
    if not top_ips:
        return '<tr><td colspan="4" class="empty">Niciun IP peste pragul de risc.</td></tr>'

    rows = []
    for ip in top_ips:
        categorii = ip.get("categories") or ""
        rows.append(
            "<tr>"
            f"<td>{_escape(ip.get('ip'))}</td>"
            f"<td>{_escape(ip.get('total'))}</td>"
            f"<td>{_escape(ip.get('max_score'))}</td>"
            f"<td>{_escape(categorii)}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def _build_flagged_table(flagged):
    """Construieste randurile de tabel HTML pentru cererile flagate."""
    if not flagged:
        return '<tr><td colspan="6" class="empty">Nicio cerere flagata.</td></tr>'

    rows = []
    for r in flagged:
        verdict = r.get("verdict") or ""
        verdict_class = f"verdict-{_escape(verdict)}"
        rows.append(
            "<tr>"
            f"<td>{_escape(r.get('timestamp'))}</td>"
            f"<td>{_escape(r.get('ip'))}</td>"
            f"<td>{_escape(r.get('method'))} {_escape(r.get('path'))}</td>"
            f"<td>{_escape(r.get('final_score'))}</td>"
            f"<td class=\"{verdict_class}\">{_escape(verdict)}</td>"
            f"<td>{_escape(r.get('top_category'))}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def _write_html(path, generated_at, summary, top_ips, flagged):
    """Scrie un raport HTML lizibil, in romana, cu doua tabele."""
    top_rows = _build_top_ips_table(top_ips)
    flagged_rows = _build_flagged_table(flagged)

    document = f"""<!DOCTYPE html>
<html lang="ro">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Raport trafic HTTP - {_escape(generated_at)}</title>
<style>
  body {{ font-family: Arial, Helvetica, sans-serif; margin: 24px; color: #1a1a1a; background: #f5f6f8; }}
  h1 {{ font-size: 22px; }}
  h2 {{ font-size: 17px; margin-top: 28px; }}
  .meta {{ color: #555; font-size: 13px; margin-bottom: 18px; }}
  .cards {{ display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 12px; }}
  .card {{ background: #fff; border: 1px solid #dcdfe4; border-radius: 8px; padding: 12px 16px; min-width: 120px; }}
  .card .val {{ font-size: 22px; font-weight: bold; }}
  .card .lbl {{ font-size: 12px; color: #666; }}
  table {{ border-collapse: collapse; width: 100%; background: #fff; margin-top: 8px; }}
  th, td {{ border: 1px solid #dcdfe4; padding: 7px 10px; text-align: left; font-size: 13px; }}
  th {{ background: #2b3a55; color: #fff; }}
  tr:nth-child(even) td {{ background: #f0f2f5; }}
  td.empty {{ text-align: center; color: #888; font-style: italic; }}
  .verdict-suspect {{ color: #b8860b; font-weight: bold; }}
  .verdict-risc_ridicat {{ color: #c0392b; font-weight: bold; }}
  .verdict-critic {{ color: #fff; background: #c0392b; font-weight: bold; }}
</style>
</head>
<body>
  <h1>Raport analiza trafic HTTP</h1>
  <div class="meta">Generat la: {_escape(generated_at)} &middot; Doar cereri cu scor final peste 30.</div>

  <div class="cards">
    <div class="card"><div class="val">{summary.get('total', 0)}</div><div class="lbl">Total cereri</div></div>
    <div class="card"><div class="val">{summary.get('suspecte', 0)}</div><div class="lbl">Suspecte</div></div>
    <div class="card"><div class="val">{summary.get('risc_ridicat', 0)}</div><div class="lbl">Risc ridicat</div></div>
    <div class="card"><div class="val">{summary.get('critice', 0)}</div><div class="lbl">Critice</div></div>
    <div class="card"><div class="val">{summary.get('anomalii', 0)}</div><div class="lbl">Anomalii</div></div>
    <div class="card"><div class="val">{summary.get('blocate', 0)}</div><div class="lbl">IP-uri blocate</div></div>
  </div>

  <h2>IP-uri periculoase</h2>
  <table>
    <thead>
      <tr><th>IP</th><th>Total cereri</th><th>Scor maxim</th><th>Categorii</th></tr>
    </thead>
    <tbody>
{top_rows}
    </tbody>
  </table>

  <h2>Cereri flagate ({len(flagged)})</h2>
  <table>
    <thead>
      <tr><th>Data</th><th>IP</th><th>Cerere</th><th>Scor final</th><th>Verdict</th><th>Categorie</th></tr>
    </thead>
    <tbody>
{flagged_rows}
    </tbody>
  </table>
</body>
</html>
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(document)


def generate_report():
    """Genereaza rapoarte JSON, HTML si CSV despre cererile flagate; intoarce caile fisierelor."""
    config.ensure_dirs()

    generated_at = datetime.now().isoformat(timespec="seconds")
    stamp = _stamp()

    # Curatam blocarile expirate ca sumarul sa reflecte starea reala.
    baza_date.unblock_expired()

    summary = baza_date.stats_summary()
    top = baza_date.top_ips(limit=20)

    # min_score=31 pastreaza doar cererile cu final_score > 30 (peste pragul de normalitate).
    flagged = baza_date.recent_requests(limit=1000, min_score=31)

    # Aducem categoriile fiecarei cereri inapoi la lista pentru raportul JSON.
    for r in flagged:
        r["categories"] = _parse_categories(r.get("categories"))

    json_path = config.REPORTS_DIR / f"raport_{stamp}.json"
    html_path = config.REPORTS_DIR / f"raport_{stamp}.html"
    csv_path = config.REPORTS_DIR / f"cereri_flagate_{stamp}.csv"

    _write_json(json_path, generated_at, summary, top, flagged)
    _write_html(html_path, generated_at, summary, top, flagged)
    _write_csv(csv_path, flagged)

    return {
        "json": str(json_path),
        "html": str(html_path),
        "csv": str(csv_path),
    }


if __name__ == "__main__":
    paths = generate_report()
    print("Rapoarte generate cu succes:")
    print("  JSON:", paths["json"])
    print("  HTML:", paths["html"])
    print("  CSV :", paths["csv"])
