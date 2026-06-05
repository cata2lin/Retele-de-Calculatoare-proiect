"""Client de test care trimite trafic catre proxy ca sa putem vedea detectia in actiune."""

# IMPORTANT: payload-urile de mai jos sunt INTENTIONAT benigne si ilustrative.
# Sunt simple siruri de caractere trimise catre serverul local de test, doar ca
# motorul de detectie sa aiba ce clasifica. Nu se executa nimic, nu se exploateaza
# nimic - scopul este strict sa demonstram ca regulile si modelul de anomalii reactioneaza.

import argparse
import time

import requests


# Timeout scurt: rulam totul local, daca nu raspunde repede ceva e in neregula
REQUEST_TIMEOUT = 10

# User-agent de browser obisnuit, ca traficul "normal" sa para uman
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


def trimite(session, base_url, method, path, **kwargs):
    """Trimite o cerere prin proxy si afiseaza pe scurt rezultatul (sau eroarea de conexiune)."""
    url = base_url.rstrip("/") + path
    try:
        resp = session.request(method, url, timeout=REQUEST_TIMEOUT, **kwargs)
        print(f"  {method:4s} {path:<45s} -> {resp.status_code}")
        return resp
    except requests.exceptions.ConnectionError:
        # Cel mai probabil proxy-ul nu ruleaza pe portul asteptat
        print(f"  {method:4s} {path:<45s} -> EROARE conexiune (proxy-ul nu raspunde)")
        return None
    except requests.exceptions.Timeout:
        print(f"  {method:4s} {path:<45s} -> EROARE timeout (proxy-ul raspunde prea greu)")
        return None


def scenariu_normal(session, base_url):
    """Trafic uman cuminte: cateva pagini vizitate intr-un ritm lejer."""
    cai = ["/", "/products", "/products/1", "/about"]
    print(f"[NORMAL] Navigare obisnuita de browser - {len(cai)} cereri")
    headers = {"User-Agent": BROWSER_UA}
    for path in cai:
        trimite(session, base_url, "GET", path, headers=headers)
        # pauza ca intre clickuri reale ale unui om
        time.sleep(0.8)


def scenariu_scraper(session, base_url):
    """Recoltare automata: multe GET-uri rapide, cale dupa cale, cu user-agent de librarie."""
    headers = {"User-Agent": "python-requests/2.31"}
    cai = [f"/products/{i}" for i in range(1, 31)]
    print(f"[SCRAPER] Recoltare rapida de pagini - {len(cai)} cereri (user-agent automat)")
    for path in cai:
        trimite(session, base_url, "GET", path, headers=headers)
        # ritm alert, tipic pentru un script de scraping
        time.sleep(0.05)


def scenariu_scanner(session, base_url):
    """Scanare de cai sensibile: cereri tipice de recunoastere, toate ar trebui sa dea 404."""
    cai = ["/admin", "/.env", "/wp-admin", "/phpmyadmin", "/server-status", "/.git/config"]
    headers = {"User-Agent": "Nmap Scripting Engine"}
    print(f"[SCANNER] Sondare cai sensibile - {len(cai)} cereri (asteptam 404)")
    for path in cai:
        trimite(session, base_url, "GET", path, headers=headers)
        time.sleep(0.2)


def scenariu_injection(session, base_url):
    """SQLi si XSS doar ca text: parametri suspecti trimisi spre /search, fara executie reala."""
    headers = {"User-Agent": BROWSER_UA}
    # parametri ilustrativi: o ghilimea + "or 1=1" pentru SQLi, o eticheta script pentru XSS
    cereri = [
        {"q": "' or 1=1 --"},
        {"q": "1' OR '1'='1"},
        {"q": "<script>alert(1)</script>"},
    ]
    print(f"[INJECTION] Tipare SQLi/XSS ca simplu text in parametri - {len(cereri)} cereri")
    for params in cereri:
        trimite(session, base_url, "GET", "/search", headers=headers, params=params)
        time.sleep(0.3)


def scenariu_traversal(session, base_url):
    """Path traversal ilustrativ: secventa dot-dot-slash catre /etc/passwd, doar ca text in cale/parametru."""
    headers = {"User-Agent": BROWSER_UA}
    # construim secventa fara s-o scriem direct, ca sa fie clar ca e doar un sir de test
    dotdot = ".." + "/"
    payload = dotdot * 4 + "etc/passwd"
    print("[TRAVERSAL] Tipar de traversare de directoare - 2 cereri")
    # o data in parametru, o data in cale, ambele variante apar des in loguri reale
    trimite(session, base_url, "GET", "/download", headers=headers, params={"file": payload})
    time.sleep(0.3)
    trimite(session, base_url, "GET", "/static/" + payload, headers=headers)
    time.sleep(0.3)


def scenariu_bruteforce(session, base_url):
    """Incercari repetate de autentificare: multe POST-uri /login cu parole gresite."""
    headers = {"User-Agent": "Python-urllib/3.10"}
    nr_incercari = 15
    print(f"[BRUTEFORCE] Incercari repetate de login cu parole gresite - {nr_incercari} cereri")
    for i in range(1, nr_incercari + 1):
        date = {"username": "admin", "password": f"parola{i}"}
        trimite(session, base_url, "POST", "/login", headers=headers, data=date)
        time.sleep(0.1)


def scenariu_dos(session, base_url):
    """Rafala de cereri: multe GET-uri pe / intr-un timp foarte scurt, ca un flood ilustrativ."""
    headers = {"User-Agent": BROWSER_UA}
    nr_cereri = 60
    print(f"[DOS] Rafala de cereri rapide catre / - {nr_cereri} cereri")
    start = time.time()
    for _ in range(nr_cereri):
        trimite(session, base_url, "GET", "/", headers=headers)
        # fara pauza: vrem sa concentram cererile pe un interval mic
    durata = time.time() - start
    print(f"  Rafala trimisa in {durata:.2f} secunde")


SCENARII = {
    "normal": scenariu_normal,
    "scraper": scenariu_scraper,
    "scanner": scenariu_scanner,
    "injection": scenariu_injection,
    "traversal": scenariu_traversal,
    "bruteforce": scenariu_bruteforce,
    "dos": scenariu_dos,
}


def ruleaza_scenariu(nume, session, base_url):
    """Ruleaza un singur scenariu dupa nume."""
    print()
    print("=" * 70)
    SCENARII[nume](session, base_url)


def proxy_disponibil(base_url):
    """Verifica rapid daca proxy-ul raspunde inainte sa pornim scenariile."""
    try:
        requests.get(base_url.rstrip("/") + "/", timeout=REQUEST_TIMEOUT)
        return True
    except requests.exceptions.RequestException:
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Generator de trafic de test pentru proxy-ul de securitate (uz local, autorizat)."
    )
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8000",
        help="Adresa proxy-ului (implicit http://127.0.0.1:8000).",
    )
    parser.add_argument(
        "--scenario",
        default="all",
        choices=["all"] + list(SCENARII.keys()),
        help="Ce scenariu sa ruleze (implicit all = toate, pe rand).",
    )
    args = parser.parse_args()

    print("Analizor de trafic HTTP - client de testare a detectiei")
    print(f"Tinta (proxy): {args.base_url}")
    print("Atentie: payload-urile sunt benigne si ilustrative, doar pentru testarea detectiei.")

    if not proxy_disponibil(args.base_url):
        print()
        print("Proxy-ul nu raspunde la adresa data.")
        print("Porneste mai intai proxy-ul (uvicorn pe portul 8000) si reincearca.")
        return

    # o singura sesiune pentru toate cererile, ca proxy-ul sa vada acelasi client
    session = requests.Session()

    if args.scenario == "all":
        # ordine logica: intai trafic curat, apoi tot ce e suspect
        for nume in ["normal", "scraper", "scanner", "injection", "traversal", "bruteforce", "dos"]:
            ruleaza_scenariu(nume, session, args.base_url)
            time.sleep(0.5)
    else:
        ruleaza_scenariu(args.scenario, session, args.base_url)

    print()
    print("=" * 70)
    print("Gata. Verifica logurile si raportul proxy-ului pentru verdictele de risc.")


if __name__ == "__main__":
    main()
