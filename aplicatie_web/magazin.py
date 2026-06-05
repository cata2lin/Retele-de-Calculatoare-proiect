"""Aplicatia reala protejata de proxy (mic site demonstrativ pe portul 8001)."""

import html

from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(title="Magazin Demo")

# Catalog simplu tinut in memorie; cheia este id-ul produsului
PRODUSE = {
    1: {"nume": "Tastatura mecanica", "pret": 249.99, "descriere": "Tastatura cu switch-uri tactile si iluminare."},
    2: {"nume": "Mouse optic", "pret": 89.50, "descriere": "Mouse usor, potrivit pentru birou si jocuri."},
    3: {"nume": "Monitor 24 inch", "pret": 749.00, "descriere": "Monitor Full HD cu rata de improspatare de 75Hz."},
    4: {"nume": "Casti audio", "pret": 159.00, "descriere": "Casti over-ear cu microfon detasabil."},
}


def pagina(titlu, continut):
    """Imbraca un fragment de continut intr-un document HTML complet."""
    return f"""<!DOCTYPE html>
<html lang="ro">
<head>
    <meta charset="utf-8">
    <title>{titlu}</title>
</head>
<body>
    <h1>{titlu}</h1>
    {continut}
    <hr>
    <p><a href="/">Acasa</a> | <a href="/products">Produse</a> | <a href="/about">Despre</a> | <a href="/login">Autentificare</a></p>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
def acasa():
    """Pagina principala cu linkuri catre celelalte sectiuni."""
    continut = """
    <p>Bine ati venit pe site-ul nostru demonstrativ.</p>
    <ul>
        <li><a href="/products">Vezi produsele</a></li>
        <li><a href="/about">Despre noi</a></li>
        <li><a href="/login">Autentificare cont</a></li>
        <li><a href="/search?q=monitor">Cauta produse</a></li>
    </ul>"""
    return pagina("Magazin Demo", continut)


@app.get("/products", response_class=HTMLResponse)
def lista_produse():
    """Afiseaza lista de produse cu legaturi catre pagina de detaliu."""
    randuri = []
    for pid, prod in PRODUSE.items():
        randuri.append(
            f'<li><a href="/products/{pid}">{html.escape(prod["nume"])}</a> '
            f'- {prod["pret"]:.2f} lei</li>'
        )
    continut = "<p>Produsele noastre disponibile:</p><ul>" + "".join(randuri) + "</ul>"
    return pagina("Produse", continut)


@app.get("/products/{produs_id}", response_class=HTMLResponse)
def detaliu_produs(produs_id: int):
    """Pagina de detaliu pentru un produs; 404 daca id-ul nu exista."""
    prod = PRODUSE.get(produs_id)
    if prod is None:
        raise HTTPException(status_code=404, detail="Produsul cautat nu a fost gasit.")
    continut = f"""
    <h2>{html.escape(prod["nume"])}</h2>
    <p><strong>Pret:</strong> {prod["pret"]:.2f} lei</p>
    <p>{html.escape(prod["descriere"])}</p>
    <p><a href="/products">Inapoi la produse</a></p>"""
    return pagina(html.escape(prod["nume"]), continut)


@app.get("/about", response_class=HTMLResponse)
def despre():
    """Pagina informativa Despre."""
    continut = """
    <p>Acesta este un magazin demonstrativ folosit pentru testarea unui analizor de trafic.</p>
    <p>Toate datele afisate aici sunt fictive si servesc doar pentru monitorizare locala.</p>"""
    return pagina("Despre", continut)


@app.get("/search", response_class=HTMLResponse)
def cautare(q: str = ""):
    """Afiseaza rezultatele cautarii; q este escapat ca sa nu apara XSS reflectat."""
    termen = html.escape(q)
    gasite = [
        prod for prod in PRODUSE.values()
        if q.strip().lower() in prod["nume"].lower()
    ]
    if termen.strip():
        antet = f"<p>Rezultate pentru: <strong>{termen}</strong></p>"
    else:
        antet = "<p>Introduceti un termen de cautare in parametrul q.</p>"

    if gasite:
        elemente = "".join(
            f"<li>{html.escape(prod['nume'])} - {prod['pret']:.2f} lei</li>"
            for prod in gasite
        )
        rezultate = "<ul>" + elemente + "</ul>"
    else:
        rezultate = "<p>Niciun produs nu corespunde cautarii.</p>"

    return pagina("Cautare", antet + rezultate)


@app.get("/login", response_class=HTMLResponse)
def formular_login():
    """Afiseaza formularul de autentificare."""
    continut = """
    <p>Introduceti datele de autentificare.</p>
    <form method="post" action="/login">
        <p><label>Utilizator: <input type="text" name="username"></label></p>
        <p><label>Parola: <input type="password" name="password"></label></p>
        <p><button type="submit">Conectare</button></p>
    </form>"""
    return pagina("Autentificare", continut)


@app.post("/login", response_class=HTMLResponse)
def proceseaza_login(username: str = Form(...), password: str = Form(...)):
    """Verifica datele de autentificare; raspunde 401 daca sunt gresite."""
    if username == "admin" and password == "parola123":
        continut = f"""
        <p>Autentificare reusita. Bine ai revenit, {html.escape(username)}.</p>
        <p>Ai acces la zona protejata a contului.</p>"""
        return pagina("Succes", continut)
    # Pentru date gresite nu dezvaluim daca a fost gresit userul sau parola
    raise HTTPException(status_code=401, detail="Date de autentificare incorecte.")


@app.get("/api/items")
def api_items():
    """Intoarce catalogul de produse sub forma de JSON."""
    items = [
        {"id": pid, "nume": prod["nume"], "pret": prod["pret"]}
        for pid, prod in PRODUSE.items()
    ]
    return JSONResponse(content={"items": items, "total": len(items)})


if __name__ == "__main__":
    import uvicorn

    print("Pornesc aplicatia reala pe http://127.0.0.1:8001")
    uvicorn.run(app, host="127.0.0.1", port=8001)
