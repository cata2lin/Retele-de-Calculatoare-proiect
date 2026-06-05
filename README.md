# Analizor de trafic HTTP

Proiectul meu pentru Retele de Calculatoare.

Pe scurt: in loc sa las o aplicatie web direct expusa, am pus in fata un fel de paznic
(un proxy) care se uita la fiecare cerere care intra, isi da seama daca pare ceva suspect
(scanere, boti, injectii, brute force etc.), ii pune un scor de risc si abia apoi o trimite
mai departe catre aplicatia adevarata. Ce se intampla se vede intr-un panou in browser.

Analiza se bazeaza pe trei lucruri: niste reguli scrise de mine, un model de anomalii
(Isolation Forest din scikit-learn) si, daca e pornit, un model de limbaj local prin Ollama.
Daca Ollama nu e pornit, merge linistit doar pe reguli + anomalii.

## Cum e organizat

- `analizor/` - aici e tot ce tine de proxy si de analiza (proxy.py, reguli, modelele, panoul, baza de date)
- `aplicatie_web/` - aplicatia adevarata pe care o protejam (un mic magazin de test), ruleaza pe 8001
- `teste/` - un script care trimite singur trafic normal si atacuri, ca sa testez detectia

Documentatia mai detaliata e in `Documentatie.pdf`.

## De ce ai nevoie

- Python 3.10 sau mai nou
- (optional) Ollama, daca vrei si partea cu model de limbaj

## Instalare

```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Pe Linux / Mac, in loc de `venv\Scripts\activate` se foloseste `source venv/bin/activate`.

## Cum se ruleaza

Am nevoie de doua terminale.

In primul pornesc aplicatia pe care o protejam (pe portul 8001):

```
python aplicatie_web/magazin.py
```

In al doilea pornesc proxy-ul (pe portul 8000):

```
python analizor/proxy.py
```

Dupa asta intru pe aplicatie PRIN proxy, din browser, la `http://localhost:8000`, iar
panoul de monitorizare e la `http://localhost:8000/dashboard`.

Daca vreau sa vad detectia fara sa dau eu cereri de mana, pornesc si scriptul de test
(intr-un al treilea terminal), care trimite trafic normal plus cateva atacuri:

```
python teste/simulare_trafic.py --scenario all
```

Modelul de anomalii se antreneaza singur la prima pornire. Daca vreau, il pot antrena si
separat cu `python analizor/model_anomalii.py`.

## Partea cu Ollama (optional)

Daca vreau si modelul de limbaj, instalez Ollama, il pornesc si descarc un model:

```
ollama serve
ollama pull llama3.2
```

Daca am deja alt model descarcat, il pot folosi fara sa modific codul, dintr-o variabila de mediu:

```
set OLLAMA_MODEL=llama3.1:8b
```

(pe Linux / Mac: `export OLLAMA_MODEL=llama3.1:8b`)

## De retinut

Sistemul doar estimeaza cat de riscanta pare o cerere, nu garanteaza ca e un atac. Unii
boti sunt legitimi, iar unii atacatori pot parea utilizatori normali. Deci rezultatul e mai
mult un semnal, nu o dovada.
