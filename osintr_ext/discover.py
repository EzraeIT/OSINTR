"""Scoperta automatica di indirizzi crypto negli endpoint e nelle pagine che il SITO STESSO cita.

Principio: si richiede solo quello che un browser richiederebbe aprendo il sito, in modo passivo:
  - solo GET, senza cookie né login, senza inviare dati;
  - solo stesso host del sito (mai domini terzi);
  - solo percorsi citati nel codice o nei link della pagina (nessun indovinare percorsi, nessun brute force);
  - esclusi i percorsi che suggeriscono azioni (logout, delete, withdraw, transfer, ...);
  - tetto di richieste (12 endpoint + 6 pagine) e di dimensione per risposta.
Se un indirizzo compare solo dopo il login o dopo un'interazione, questo modulo non lo vede: va passato con --address.
"""
from __future__ import annotations

import re
import urllib.parse
from typing import Optional

from .addresses import find_addresses
from .util import sha256_bytes

MAX_ENDPOINTS = 80
MAX_PAGES = 12
MAX_BODY = 512 * 1024

STATIC_EXT = re.compile(r"\.(?:js|mjs|css|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|otf|eot|map|mp4|webm|mp3|pdf|zip)(?:$|\?)", re.I)
DENY = re.compile(r"(?i)(log(?:out|off)|sign(?:out|off)|delete|remove|cancel|withdraw|transfer|confirm|approve|reset|"
                  r"unsubscribe|activate|admin|upload|checkout|send|exec|drop|clear)")
PAGE_HINT = re.compile(r"(?i)(deposit|wallet|invest|fund|plan|pricing|faq|how|about|contact|payment|stak|earn|finance|"
                       r"topup|recharge|address|terms|legal|privacy|account|profile|kyc|verif|arbitr|trad|order|"
                       r"histor|statement|report|dashboard|return|profit|yield)")

# categorie di campi "interessanti" nella risposta di un endpoint, per nome di chiave JSON o parola nel testo.
# Servono solo a segnalare all'analista dove guardare: non provano che i dati siano reali o utilizzabili.
FIELD_CATEGORIES: dict[str, re.Pattern] = {
    "wallet_saldo": re.compile(r"(?i)\b(balance|saldo|available_balance|wallet_balance|deposit_address|"
                                r"withdraw(?:al)?|prelievo|deposito)\b"),
    "transazioni": re.compile(r"(?i)\b(transactions?|transfers?|movements?|tx_?hash|txid|movimenti)\b"),
    "arbitraggio_trading": re.compile(r"(?i)\b(arbitrage|arbitraggio|trade|trading|order_?book|exchange_?rate|"
                                      r"spread|pair)\b"),
    "rendimenti_commissioni": re.compile(r"(?i)\b(profit|rendimento|yield|roi|interest_?rate|commission|fee|"
                                         r"referral|bonus)\b"),
    "account_profilo": re.compile(r"(?i)\b(account_?id|user_?id|username|email|kyc|verification|profile|"
                                   r"full_?name)\b"),
    "cronologia_statistiche": re.compile(r"(?i)\b(history|statement|report|stats?|total_(?:deposit|profit|"
                                         r"volume)|daily_)\b"),
}
AUTH_HINT = re.compile(r"(?i)\b(sign[\s_-]?in|log[\s_-]?in|unauthorized|unauthenticated|authentication required|"
                       r"accesso richiesto|effettua il login)\b")
# chiamate di rete nel JavaScript: fetch / axios / $.get / $.getJSON / $http.get
CALL_RE = re.compile(r"""(?:fetch|axios(?:\.get)?|\$\.(?:get|getJSON|ajax)|\$http\.get|"""
                     r"""(?:api|http|client|rest|service|backend)\w*\.get)\s*\(\s*(['"`])([^'"`\s]{2,200})\1""", re.I)
URL_KEY_RE = re.compile(r"""\burl\s*:\s*(['"`])([^'"`\s]{2,200})\1""")
LITERAL_RE = re.compile(r"""(['"`])((?:https?:)?//[^'"`\s]{3,200}|/[A-Za-z0-9_\-./]*(?:api|ajax|json|wallet|deposit|finance|payment|address|config|settings)[A-Za-z0-9_\-./?=&]*|[A-Za-z0-9_\-./]+\.(?:php|json|aspx?|do)(?:\?[A-Za-z0-9_=&%.\-]*)?)\1""")
# Un nome di chiave come "url:" o una chiamata .get(...) non bastano: il valore va comunque validato come percorso
# plausibile. Senza questo, framework interni (es. Next.js) che usano "url" o ".get(...)" per cose che non sono
# URL (nomi di header, chiavi di cache, placeholder di template literal "${...}") venivano scambiati per endpoint.
HTTP_HEADER_NAME = re.compile(r"(?i)^(?:[a-z0-9]+-){1,5}[a-z0-9]+$")   # es. "X-Vinext-Params", "Content-Type"


def _looks_like_path(cand: str) -> bool:
    if not cand or "${" in cand or "`" in cand or " " in cand or "\n" in cand:
        return False   # template literal non risolto, o non e' un token singolo
    if cand.startswith(("http://", "https://", "//")):
        return True
    if cand.startswith("/") and len(cand) > 1 and not cand.startswith("//"):
        return re.fullmatch(r"/[A-Za-z0-9_\-./%]*(?:\?[A-Za-z0-9_=&%.\-]*)?", cand) is not None
    if HTTP_HEADER_NAME.match(cand):
        return False    # "X-Vinext-Params", "Content-Type": nomi di header, non percorsi
    # relativo senza slash iniziale: accettato solo con estensione o parola chiave di endpoint, e almeno un "/" o "."
    return bool(re.fullmatch(r"[A-Za-z0-9_\-./]+\.(?:php|json|aspx?|do)(?:\?[A-Za-z0-9_=&%.\-]*)?", cand))
WRITE_KEY = re.compile(r"""(?i)\b(?:type|method)\s*:\s*['"](?:post|put|delete|patch)['"]""")
WRITE_CALLEE = re.compile(r"(?i)(?:\.|\b)(?:post|put|delete|patch)\s*$")
WRITE_OPEN = re.compile(r"""(?i)^\(\s*['"](?:post|put|delete|patch)['"]""")


def _call_span(code: str, pos: int) -> Optional[tuple[int, int]]:
    """Intervallo della chiamata di funzione `f( ... )` che contiene la posizione `pos` (None se non e' in una chiamata)."""
    depth, i = 0, pos - 1
    start = None
    while i >= max(0, pos - 400):
        ch = code[i]
        if ch == ")":
            depth += 1
        elif ch == "(":
            if depth == 0:
                start = i
                break
            depth -= 1
        i -= 1
    if start is None:
        return None
    depth, j = 0, start
    while j < min(len(code), start + 800):
        if code[j] == "(":
            depth += 1
        elif code[j] == ")":
            depth -= 1
            if depth == 0:
                return start, j
        j += 1
    return start, min(len(code), start + 800)


def _is_write(code: str, pos: int) -> bool:
    """True se il letterale in `pos` e' argomento di una chiamata di scrittura (post/put/delete/patch, type/method: POST, open('POST'))."""
    span = _call_span(code, pos)
    if span is None:
        return bool(re.search(r"(?i)\b(?:post|put|delete|patch)\b[^;\n]{0,30}$", code[max(0, pos - 40):pos]))
    start, end = span
    body = code[start:end + 1]
    return bool(WRITE_CALLEE.search(code[max(0, start - 25):start]) or WRITE_KEY.search(body) or WRITE_OPEN.search(body))


def _host(u: str) -> str:
    return urllib.parse.urlparse(u).netloc.lower().removeprefix("www.")


BAD_CANDIDATE = re.compile(r"\$\{|`")                      # frammento di template literal non risolto
PATH_EXT_RE = re.compile(r"\.(?:php|json|aspx?|do)(?:\?|$)", re.I)


def _looks_like_path(cand: str) -> bool:
    """Un candidato e' richiesto solo se somiglia davvero a un URL/percorso: scarta nomi di header HTTP
    (es. 'content-type', 'X-Vinext-Rsc-...'), chiavi generiche e placeholder di template literal irrisolti,
    che una qualsiasi chiamata .get() di un Map/Headers/URLSearchParams puo' restituire come falso positivo."""
    if BAD_CANDIDATE.search(cand):
        return False
    if cand.startswith(("http://", "https://", "//", "/")):
        return True
    return bool(PATH_EXT_RE.search(cand))


def endpoint_candidates(code: str) -> list[str]:
    """Percorsi/URL citati nel codice che sembrano richieste di lettura. Se il contesto lascia pensare a una scrittura
    (POST/PUT/DELETE/PATCH nelle vicinanze) il candidato viene scartato: nel dubbio non si richiede."""
    out: list[str] = []
    for rx in (CALL_RE, URL_KEY_RE, LITERAL_RE):
        for m in rx.finditer(code):
            cand = m.group(2)
            if not _looks_like_path(cand) or _is_write(code, m.start(2)):
                continue
            if cand not in out:
                out.append(cand)
    return out


def _acceptable(full: str, base_host: str, seen: set[str]) -> bool:
    pu = urllib.parse.urlparse(full)
    if pu.scheme not in ("http", "https") or _host(full) != base_host:
        return False
    key = pu.path + ("?" + pu.query if pu.query else "")
    if full in seen or not pu.path or pu.path == "/" or STATIC_EXT.search(key) or DENY.search(key):
        return False
    return True


def _looks_textual(r) -> bool:
    ct = r.headers.get("content-type", "").lower()
    if any(k in ct for k in ("json", "text", "xml", "javascript")):
        return True
    return r.body[:1] in (b"{", b"[", b"<")


def _json_keys(body: bytes, depth: int = 0, out: Optional[set] = None) -> set:
    """Nomi di chiave in un JSON (ricorsivo, profondita' limitata). Ritorna un insieme vuoto se non e' JSON valido."""
    import json
    out = set() if out is None else out
    if depth == 0:
        try:
            obj = json.loads(body)
        except (ValueError, TypeError):
            return out
    else:
        obj = body
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.add(str(k))
            if depth < 4:
                _json_keys(v, depth + 1, out)
    elif isinstance(obj, list):
        for v in obj[:20]:
            if depth < 4:
                _json_keys(v, depth + 1, out)
    return out


def categorize_response(body: bytes) -> dict:
    """Riconosce campi interessanti in una risposta (JSON: per nome di chiave; altrimenti: parole nel testo).
    Ritorna {'fields': [...], 'categories': [...], 'auth_required': bool}. Un'etichetta riconosciuta e' un indicatore,
    non una prova che l'endpoint contenga dati finanziari reali o utilizzabili."""
    keys = _json_keys(body)
    try:
        text = body.decode("utf-8", "ignore")
    except Exception:
        text = ""
    haystack = " ".join(keys) if keys else text[:4000]
    fields, cats = [], []
    for cat, rx in FIELD_CATEGORIES.items():
        hit = rx.search(haystack)
        if hit:
            cats.append(cat)
            fields.append(hit.group(0))
    return {"fields": sorted(set(fields)), "categories": cats, "auth_required": bool(AUTH_HINT.search(text[:2000]))}


def discover(http, page_url: str, js_sources: list[tuple[str, str]], links: list[str], already: list[str],
             max_endpoints: int = MAX_ENDPOINTS, max_pages: int = MAX_PAGES) -> dict:
    """Ritorna {'endpoints': [...], 'pages': [...], 'probed': [...], 'addresses': [...], 'skipped': n}."""
    base_host = _host(page_url)
    seen = set(already) | {page_url}
    res: dict = {"endpoints": [], "pages": [], "addresses": [], "skipped": 0}
    found: dict[tuple[str, str], dict] = {}

    def record(items, source: str):
        for a in items:
            d = a.to_dict()
            d["source"] = source
            found.setdefault((d["family"], d["address"].lower()), d)

    # --- endpoint citati nel codice JS (e inline)
    cands: list[str] = []
    for _, code in js_sources:
        for c in endpoint_candidates(code):
            full = urllib.parse.urljoin(page_url, c)
            if full not in cands:
                cands.append(full)
    n = 0
    for full in cands:
        if not _acceptable(full, base_host, seen):
            res["skipped"] += 1
            continue
        if n >= max_endpoints:
            res["skipped"] += 1
            continue
        seen.add(full)
        n += 1
        r = http.get(full)
        entry = {"url": full, "status": r.status, "size": len(r.body), "content_type": r.headers.get("content-type", ""),
                "addresses": [], "fields": [], "categories": [], "auth_required": False}
        if r.body and len(r.body) <= MAX_BODY:
            cat = categorize_response(r.body)
            entry.update(cat)
        if r.ok and len(r.body) <= MAX_BODY and _looks_textual(r) and not entry["auth_required"]:
            entry["sha256"] = sha256_bytes(r.body)
            hits = find_addresses(r.text, urllib.parse.urlparse(full).path)
            entry["addresses"] = [a.address for a in hits]
            record(hits, "endpoint:" + urllib.parse.urlparse(full).path)
        res["endpoints"].append(entry)

    # --- pagine interne linkate che di solito mostrano dati di pagamento
    pages: list[str] = []
    for href in links:
        full = urllib.parse.urljoin(page_url, href).split("#")[0]
        path = urllib.parse.urlparse(full).path
        if PAGE_HINT.search(path) and _acceptable(full, base_host, seen) and full not in pages:
            pages.append(full)
    for full in pages[:max_pages]:
        seen.add(full)
        r = http.get(full)
        entry = {"url": full, "status": r.status, "size": len(r.body), "content_type": r.headers.get("content-type", ""),
                "addresses": [], "fields": [], "categories": [], "auth_required": False}
        if r.body and len(r.body) <= MAX_BODY:
            entry.update(categorize_response(r.body))
        if r.ok and len(r.body) <= MAX_BODY and not entry["auth_required"]:
            hits = find_addresses(r.text, urllib.parse.urlparse(full).path)
            entry["addresses"] = [a.address for a in hits]
            record(hits, "page:" + urllib.parse.urlparse(full).path)
        res["pages"].append(entry)
    res["skipped"] += max(0, len(pages) - max_pages)

    # --- ricognizione attiva opzionale: percorsi plausibili NON citati dal sito
    res["addresses"] = list(found.values())
    return res
