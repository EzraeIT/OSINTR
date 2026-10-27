"""Scansione *passiva* di un sito: una pagina, i suoi script same-site e poche pagine legali.

Nessun login, nessun bypass, nessuna richiesta anomala: solo GET di risorse pubbliche, con throttling.
Le euristiche producono *indicatori* da rivedere a mano, non verdetti.
"""
from __future__ import annotations

import hashlib
import os
import re
import urllib.parse
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Optional

from .addresses import find_addresses
from .entity import find_company_mentions
from .util import Finding, sha256_bytes

FIN_KEYWORDS = ("profit", "spread", "amount", "deal", "arbitrag", "exchange", "trade", "bought", "sold",
                "pair", "yield", "earning")
FEED_WORDS = ("deal", "trade", "transaction", "recent", "last", "payout", "withdraw", "arbitrage")
LEGAL_HREF = re.compile(r"(terms|privacy|legal|imprint|impressum|condizion|terminos|termos|aviso|cookie|"
                        r"disclaimer|risk|policy)", re.I)
LEGAL_COMMON = ("/terms", "/privacy", "/terms-of-service", "/privacy-policy", "/legal", "/about")

PERIODS = {
    "daily": r"(daily|per day|a day|/day|each day|every day|al giorno|giornalier|ogni giorno|diari|por dia|"
             r"por día|täglich|taeglich|par jour|quotidien)",
    "weekly": r"(weekly|per week|a week|/week|settiman|a settimana|semanal|por semana|wöchentlich|"
              r"hebdomadaire)",
    "monthly": r"(monthly|per month|a month|/month|al mese|mensil|mensual|por mês|por mes|monatlich|"
               r"par mois|mensuel)",
    "yearly": r"(yearly|annual|per year|a year|/year|all'anno|annuo|annual|por ano|por año|jährlich|par an)",
}
ANNUALISE = {"daily": 365, "weekly": 52, "monthly": 12, "yearly": 1}
GUARANTEE_RE = re.compile(r"(guarantee[sd]?|risk[- ]free|zero risk|no risk|100% safe|garantit\w+|"
                          r"senza rischi\w*|nessun rischio|sin riesgo|garantizad\w+|sem risco|garantid\w+|"
                          r"ohne risiko|sans risque)", re.I)
PRESSURE_RE = re.compile(r"(limited (?:time|spots|offer)|only \d+ (?:spots|places)|last chance|act now|"
                         r"offerta limitata|ultimi posti|solo per oggi|oferta limitada|nur noch)", re.I)
REFERRAL_RE = re.compile(r"(referral|affiliate|invite|partner program|parrain|referid|indica|invita|"
                         r"parceri|empfehl)", re.I)
PCT_RE = re.compile(r"(\d{1,3}(?:[.,]\d{1,2})?)\s?%")
SECURITY_HEADERS = {
    "content-security-policy": "CSP",
    "strict-transport-security": "HSTS",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
}


# --------------------------------------------------------------------------- parsing HTML
class _Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: list[str] = []
        self.inline: list[str] = []
        self.links: list[str] = []
        self.text: list[str] = []
        self.title = ""
        self._skip = 0
        self._in_title = False
        self._cur: Optional[list[str]] = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script":
            if a.get("src"):
                self.scripts.append(a["src"])
            else:
                self._cur = []
            self._skip += 1
        elif tag == "style":
            self._skip += 1
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "script":
            self._skip = max(0, self._skip - 1)
            if self._cur is not None:
                self.inline.append("".join(self._cur))
                self._cur = None
        elif tag == "style":
            self._skip = max(0, self._skip - 1)
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._cur is not None:
            self._cur.append(data)
        elif self._in_title:
            self.title += data
        elif not self._skip:
            t = data.strip()
            if t:
                self.text.append(t)


def parse_html(html: str) -> _Page:
    p = _Page()
    try:
        p.feed(html)
    except Exception:  # HTML malformato: teniamo quanto raccolto
        pass
    return p


def _snip(s: str, n: int = 220) -> str:
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= n else s[: n - 3] + "..."


# --------------------------------------------------------------------------- analisi JS
def analyze_js(name: str, code: str) -> dict:
    out = {"file": name, "random_hits": [], "feed": [], "uploads": False}
    for m in re.finditer(r"Math\.random\s*\(|crypto\.getRandomValues", code):
        a, b = max(0, m.start() - 300), min(len(code), m.end() + 300)
        win = code[a:b].lower()
        kws = sorted({k for k in FIN_KEYWORDS if k in win})
        if len(kws) >= 2:
            wide = code[max(0, m.start() - 1200): m.end() + 1200].lower()
            posted = bool(re.search(r"(method\s*:\s*['\"]post|\.post\s*\(|type\s*:\s*['\"]post|xmlhttprequest)", wide)) \
                and bool(re.search(r"(\.php|/api/|url\s*:)", wide))
            out["random_hits"].append({"offset": m.start(), "keywords": kws, "uploaded": posted,
                                       "snippet": _snip(code[a:b])})
            out["uploads"] = out["uploads"] or posted
    for m in re.finditer(r"setInterval\s*\(", code):
        win = code[m.start(): m.start() + 900]
        if re.search(r"(fetch\s*\(|\.ajax\s*\(|xmlhttprequest|\$\.(?:get|post)|\.get\s*\()", win, re.I):
            for e in re.findall(r"""["'`]([\w./-]*(?:%s)[\w./?=&-]*)["'`]""" % "|".join(FEED_WORDS), win, re.I):
                if e not in out["feed"]:
                    out["feed"].append(e)
    return out


# --------------------------------------------------------------------------- analisi testo
def analyze_text(text: str) -> dict:
    rates: list[dict] = []
    seen = set()
    for m in PCT_RE.finditer(text):
        after = text[m.end(): m.end() + 45].lower()
        before = text[max(0, m.start() - 20): m.start()].lower()
        best = None                       # (distanza, periodo): vince la parola-periodo più vicina al numero
        for period, pat in PERIODS.items():
            ma = re.search(pat, after)
            if ma and (best is None or ma.start() < best[0]):
                best = (ma.start(), period)
            mb = None
            for mb in re.finditer(pat, before):
                pass
            if mb and (best is None or len(before) - mb.end() < best[0]):
                best = (len(before) - mb.end(), period)
        if best:
            period = best[1]
            v = float(m.group(1).replace(",", "."))
            if 0 < v <= 100 and (v, period) not in seen:
                seen.add((v, period))
                rates.append({"rate": v, "period": period, "annual": round(v * ANNUALISE[period], 1),
                              "snippet": _snip(text[max(0, m.start() - 50): m.end() + 60], 140)})
    guarantees = sorted({m.group(1).lower() for m in GUARANTEE_RE.finditer(text)})[:5]
    pressure = sorted({m.group(1).lower() for m in PRESSURE_RE.finditer(text)})[:5]
    referral = []
    for m in REFERRAL_RE.finditer(text):
        seg = text[m.start(): m.end() + 90]
        p = PCT_RE.search(seg)
        if p and p.group(1) not in referral:
            referral.append(p.group(1) + "%")
    return {"rates": rates, "guarantees": guarantees, "pressure": pressure, "referral": referral[:4]}


def _cookie_issues(set_cookies: list[str]) -> list[str]:
    issues = []
    for c in set_cookies:
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        miss = [a for a, k in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite"))
                if k not in low]
        if miss:
            issues.append(f"{name} ({', '.join(miss)})")
    return issues


# --------------------------------------------------------------------------- scansione
def scan_site(http, url: str, max_js: int = 12, save_dir: Optional[str] = None,
              now: Optional[datetime] = None, discover_enabled: bool = True) -> dict:
    if not re.match(r"^https?://", url):
        url = "https://" + url
    now = now or datetime.now(timezone.utc)
    page_r = http.get(url)
    res: dict = {"url": url, "final_url": page_r.url, "status": page_r.status, "error": page_r.error,
                 "fetched_at": now.isoformat(timespec="seconds"), "js_files": [], "legal_pages": [],
                 "addresses": [], "random_hits": [], "feed": [], "uploads": False,
                 "endpoints": [], "pages": [], "endpoints_skipped": 0}
    if not page_r.ok and not page_r.body:
        return res
    html = page_r.text
    host = urllib.parse.urlparse(page_r.url).netloc
    res["html_sha256"] = sha256_bytes(page_r.body)
    p = parse_html(html)
    res["title"] = _snip(p.title, 120)
    res["server"] = page_r.headers.get("server", "")
    res["x_powered_by"] = page_r.headers.get("x-powered-by", "")
    res["security_headers"] = {label: (h in page_r.headers) for h, label in SECURITY_HEADERS.items()}
    res["cors"] = {"acao": page_r.headers.get("access-control-allow-origin", ""),
                   "acac": page_r.headers.get("access-control-allow-credentials", "")}
    res["cookie_issues"] = _cookie_issues(page_r.set_cookies)

    if save_dir:
        os.makedirs(os.path.join(save_dir, "js"), exist_ok=True)
        with open(os.path.join(save_dir, "index.html"), "wb") as f:
            f.write(page_r.body)

    visible = " ".join(p.text)
    res["text"] = analyze_text(visible)
    res["company_mentions"] = find_company_mentions(visible)
    res["addresses"] = [a.to_dict() for a in find_addresses(html, page_r.url)]

    # script: inline + same-site (stesso host o sottodomini)
    sources: list[tuple[str, str]] = [(f"inline#{i + 1}", c) for i, c in enumerate(p.inline) if c.strip()]
    fetched = 0
    for src in p.scripts:
        full = urllib.parse.urljoin(page_r.url, src)
        sh = urllib.parse.urlparse(full).netloc
        if not (sh == host or sh.endswith("." + host.removeprefix("www."))):
            continue
        if fetched >= max_js:
            break
        r = http.get(full)
        fetched += 1
        if r.ok:
            name = urllib.parse.urlparse(full).path.rsplit("/", 1)[-1] or full
            res["js_files"].append({"url": full, "size": len(r.body), "sha256": sha256_bytes(r.body)})
            sources.append((name, r.text))
            if save_dir:
                safe = re.sub(r"[^\w.-]", "_", name)[:80]
                with open(os.path.join(save_dir, "js", safe), "wb") as f:
                    f.write(r.body)
            if r.headers.get("access-control-allow-origin") == "*" and not res["cors"]["acao"]:
                res["cors"] = {"acao": "*", "acac": r.headers.get("access-control-allow-credentials", "")}

    addrs = {(a["family"], a["address"].lower()): a for a in res["addresses"]}
    for name, code in sources:
        js = analyze_js(name, code)
        res["random_hits"] += [{**h, "file": name} for h in js["random_hits"]]
        res["uploads"] = res["uploads"] or js["uploads"]
        for e in js["feed"]:
            if e not in res["feed"]:
                res["feed"].append(e)
        for a in find_addresses(code, name):
            addrs.setdefault((a.family, a.address.lower()), a.to_dict())
    res["addresses"] = list(addrs.values())

    # endpoint e pagine che il sito stesso cita (solo GET, stesso host): qui compaiono spesso gli indirizzi di deposito
    res["endpoints"], res["pages"], res["endpoints_skipped"] = [], [], 0
    if discover_enabled:
        from .discover import discover
        d = discover(http, page_r.url, sources, p.links, [j["url"] for j in res["js_files"]])
        res["endpoints"], res["pages"], res["endpoints_skipped"] = d["endpoints"], d["pages"], d["skipped"]
        for a in d["addresses"]:
            addrs.setdefault((a["family"], a["address"].lower()), a)
        res["addresses"] = list(addrs.values())

    # pagine legali
    cands: list[str] = []
    for href in p.links:
        if LEGAL_HREF.search(href):
            full = urllib.parse.urljoin(page_r.url, href)
            if urllib.parse.urlparse(full).netloc == host and full not in cands:
                cands.append(full)
    res["legal_links_found"] = bool(cands)
    if not cands:
        base = f"{urllib.parse.urlparse(page_r.url).scheme}://{host}"
        cands = [base + c for c in LEGAL_COMMON[:3]]
    for full in cands[:5]:
        r = http.get(full)
        if r.ok:
            t = " ".join(parse_html(r.text).text)
            res["legal_pages"].append({"url": full, "chars": len(t)})
    return res


# --------------------------------------------------------------------------- finding dal sito
OLD_PHP = re.compile(r"php/(\d+)\.(\d+)", re.I)


def site_findings(scan: dict) -> list[Finding]:
    fs: list[Finding] = []
    if not scan.get("status"):
        return fs
    t = scan.get("text", {})

    hits = scan.get("random_hits", [])
    if hits:
        kws = sorted({k for h in hits for k in h["keywords"]})
        files = sorted({h["file"] for h in hits})
        params = {"keywords": ", ".join(kws), "files": ", ".join(files[:4])}
        if scan.get("uploads") and len(kws) >= 3:
            fs.append(Finding("CODE_RANDOM_UPLOADED", "critical", "medium-high", "interpretation", "code",
                              "JavaScript pubblico (analisi statica)", params))
        else:
            fs.append(Finding("CODE_RANDOM_DATA", "high", "medium", "interpretation", "code",
                              "JavaScript pubblico (analisi statica)", params))
    if scan.get("feed"):
        fs.append(Finding("CODE_FEED_POLLING", "medium", "medium", "interpretation", "code",
                          "JavaScript pubblico (analisi statica)", {"endpoints": ", ".join(scan["feed"][:4])}))

    rates = t.get("rates", [])
    big = [r for r in rates if r["annual"] >= 50]
    if big:
        top = max(big, key=lambda r: r["annual"])
        extreme = any((r["period"] == "daily" and r["rate"] >= 1) or (r["period"] == "weekly" and r["rate"] >= 5)
                      or (r["period"] == "monthly" and r["rate"] >= 10) for r in big)
        sev = "critical" if extreme else ("high" if top["annual"] >= 100 else "medium")
        fs.append(Finding("ECO_HIGH_RETURN", sev, "medium", "interpretation", "economics", "Testo del sito",
                          {"rates": "; ".join(f"{r['rate']:g}% {r['period']} (~{r['annual']:g}%/yr)"
                                              for r in sorted(big, key=lambda r: -r["annual"])[:4])}))
    ann = sorted({r["annual"] for r in rates})
    if len(ann) >= 2 and ann[-1] / max(ann[0], 0.01) >= 2:
        fs.append(Finding("ECO_INCONSISTENT", "high", "medium", "interpretation", "economics", "Testo del sito",
                          {"rates": "; ".join(f"{r['rate']:g}% {r['period']}" for r in rates[:5])}))
    if t.get("guarantees"):
        fs.append(Finding("ECO_GUARANTEED", "high", "medium-high", "fact", "economics", "Testo del sito",
                          {"phrases": ", ".join(t["guarantees"])}))
    if t.get("referral"):
        fs.append(Finding("ECO_REFERRAL", "medium", "medium", "interpretation", "economics", "Testo del sito",
                          {"pct": ", ".join(t["referral"])}))
    if t.get("pressure"):
        fs.append(Finding("ECO_PRESSURE", "low", "medium", "fact", "economics", "Testo del sito",
                          {"phrases": ", ".join(t["pressure"])}))

    cm = scan.get("company_mentions", {})
    if not cm.get("names") and not cm.get("ids"):
        fs.append(Finding("ENT_NO_ENTITY", "high", "medium-high", "fact", "entity", "Testo del sito", {}))

    legal = scan.get("legal_pages", [])
    thin = [x for x in legal if x["chars"] < 400]
    if not scan.get("legal_links_found") and not legal:
        fs.append(Finding("WEB_LEGAL_MISSING", "high", "medium-high", "fact", "web", "Navigazione del sito", {}))
    elif thin:
        fs.append(Finding("WEB_LEGAL_THIN", "high", "high", "fact", "web", "Pagine legali",
                          {"pages": ", ".join(f"{x['url']} ({x['chars']} car.)" for x in thin[:3])}))

    server = " ".join(x for x in (scan.get("server", ""), scan.get("x_powered_by", "")) if x)
    m = OLD_PHP.search(server)
    if m and (int(m.group(1)), int(m.group(2))) < (8, 2):
        fs.append(Finding("WEB_OLD_SERVER", "medium", "medium-high", "fact", "web", "Header HTTP",
                          {"server": server}))
    missing = [k for k, v in scan.get("security_headers", {}).items() if not v]
    if len(missing) >= 3:
        fs.append(Finding("WEB_HEADERS_MISSING", "low", "high", "fact", "web", "Header HTTP",
                          {"missing": ", ".join(missing)}))
    cors = scan.get("cors", {})
    if cors.get("acao") == "*":
        sev = "medium" if cors.get("acac", "").lower() == "true" else "low"
        fs.append(Finding("WEB_CORS", sev, "medium", "fact", "web", "Header HTTP",
                          {"acao": cors["acao"], "acac": cors.get("acac") or "n/d"}))
    if scan.get("cookie_issues"):
        fs.append(Finding("WEB_COOKIES", "low", "high", "fact", "web", "Header HTTP",
                          {"cookies": "; ".join(scan["cookie_issues"][:4])}))
    return fs
