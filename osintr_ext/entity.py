"""Controlli societari e di dominio a copertura mondiale.

Senza chiavi API:
  - VIES (partite IVA di tutti i paesi UE + XI) - conferma validità e, dove disponibile, nome/indirizzo.
  - GLEIF (codici LEI, tutto il mondo) - ricerca per denominazione.
  - RDAP (via rdap.org) - data di registrazione, scadenza, registrar e nameserver del dominio.
Con chiavi opzionali (variabili d'ambiente):
  - OPENCORPORATES_API_KEY  -> registri societari di ~140 giurisdizioni
  - COMPANIES_HOUSE_KEY     -> registro del Regno Unito
  - OPENSANCTIONS_API_KEY   -> sanzioni / PEP / watchlist per nome

Nota: l'assenza di un record NON prova nulla (molte società non hanno LEI né compaiono nei registri aperti).
Per uso giudiziario servono visura/certificato ufficiali del registro competente.
"""
from __future__ import annotations

import base64
import re
import urllib.parse
from datetime import date, datetime, timezone
from typing import Optional

from . import registries
from .util import Finding

LEGAL_SUFFIX = r"(?:LLC|L\.L\.C\.|Ltd\.?|Limited|GmbH|S\.?r\.?l\.?|S\.?p\.?A\.?|S\.?A\.?S?\.?|Lda\.?|LDA|Unipessoal|Inc\.?|Corp\.?|OÜ|B\.?V\.?|N\.?V\.?|AG|Pty|Pte|Sdn Bhd|Ltda\.?|S\.?L\.?|Oy|AB|ApS|FZE|FZCO|FZ-LLC)"
COMPANY_RE = re.compile(rf"([A-Z][\w&.,'’\-]*(?:\s+[A-Z0-9][\w&.,'’\-]*){{0,5}}\s+{LEGAL_SUFFIX}(?:\s+{LEGAL_SUFFIX})?)(?![\w])")
VAT_RE = re.compile(r"\b(?:VAT|IVA|NIPC|NIF|P\.?\s?IVA|Tax ID|Company (?:No|Number)|Reg(?:istration)?\.? ?(?:No|Number))\b[\s:.#-]*([A-Z]{0,2}\s?\d[\d\s.-]{5,16}\d)", re.I)


def find_company_mentions(text: str) -> dict:
    names = []
    for m in COMPANY_RE.finditer(text):
        n = re.sub(r"\s+", " ", m.group(1)).strip(" ,.")
        if n not in names and len(n) < 90:
            names.append(n)
    ids = []
    for m in VAT_RE.finditer(text):
        v = re.sub(r"[\s.-]", "", m.group(1))
        if v not in ids:
            ids.append(v)
    return {"names": names[:5], "ids": ids[:5]}


def parse_vat(vat: Optional[str], country: Optional[str]) -> tuple[str, str]:
    """'PT123456789' -> ('PT','123456789'); '123456789' + country 'PT' -> ('PT','123456789')."""
    if not vat:
        return "", ""
    v = re.sub(r"[\s.-]", "", vat).upper()
    m = re.match(r"^([A-Z]{2})(\w{4,})$", v)
    if m:
        return m.group(1), m.group(2)
    return (country or "").upper(), v


def _norm_name(s: str) -> set[str]:
    s = re.sub(rf"\b{LEGAL_SUFFIX}\b", " ", s, flags=re.I)
    return {t for t in re.sub(r"[^\w]+", " ", s.casefold()).split() if len(t) > 1}


def name_similarity(a: str, b: str) -> float:
    ta, tb = _norm_name(a), _norm_name(b)
    return len(ta & tb) / max(1, min(len(ta), len(tb))) if ta and tb else 0.0


# --------------------------------------------------------------------------- sorgenti
EU_VIES = {"AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "EL", "GR", "ES", "FI", "FR", "HR", "HU", "IE", "IT",
           "LT", "LU", "LV", "MT", "NL", "PL", "PT", "RO", "SE", "SI", "SK", "XI"}


def vies_check(http, cc: str, num: str) -> Optional[dict]:
    cc = "EL" if cc == "GR" else cc
    d = http.get_json(f"https://ec.europa.eu/taxation_customs/vies/rest-api/ms/{cc}/vat/{num}")
    if not isinstance(d, dict) or "isValid" not in d:
        return None
    clean = lambda x: None if not x or x.strip() in ("---", "") else x.strip()
    return {"valid": bool(d.get("isValid")), "name": clean(d.get("name")),
            "address": clean(d.get("address")), "country": cc, "number": num}


def cnpj_lookup(http, cnpj: str) -> Optional[dict]:
    """Brasile: dati pubblici del CNPJ via BrasilAPI (senza chiave). Ritorna None se non trovato."""
    import re as _re
    digits = _re.sub(r"\D", "", cnpj or "")
    if len(digits) != 14:
        return None
    d = http.get_json(f"https://brasilapi.com.br/api/cnpj/v1/{digits}")
    if not isinstance(d, dict) or not d.get("cnpj"):
        return None
    return {"cnpj": digits, "name": d.get("razao_social"), "trade_name": d.get("nome_fantasia"),
            "status": d.get("descricao_situacao_cadastral"), "opened": d.get("data_inicio_atividade"),
            "cnae": d.get("cnae_fiscal_descricao"), "capital": d.get("capital_social"),
            "uf": d.get("uf")}


def gleif_search(http, name: str) -> list[dict]:
    q = urllib.parse.quote(name, safe="")
    d = http.get_json("https://api.gleif.org/api/v1/lei-records?filter%5Bentity.legalName%5D="
                      f"{q}&page%5Bsize%5D=5")
    out = []
    for r in (d or {}).get("data", []):
        a = r.get("attributes", {})
        e = a.get("entity", {})
        out.append({"lei": a.get("lei"), "name": (e.get("legalName") or {}).get("name"),
                    "status": e.get("status"), "jurisdiction": e.get("jurisdiction"),
                    "country": (e.get("legalAddress") or {}).get("country"),
                    "registered_as": e.get("registeredAs")})
    return out


def opencorporates_search(http, name: str, key: str, jurisdiction: Optional[str] = None) -> list[dict]:
    q = urllib.parse.quote(name)
    url = f"https://api.opencorporates.com/v0.4/companies/search?q={q}&api_token={key}"
    if jurisdiction:
        url += f"&jurisdiction_code={jurisdiction.lower()}"
    d = http.get_json(url)
    out = []
    for c in ((d or {}).get("results") or {}).get("companies", [])[:5]:
        c = c.get("company", {})
        out.append({"name": c.get("name"), "number": c.get("company_number"),
                    "jurisdiction": c.get("jurisdiction_code"), "incorporated": c.get("incorporation_date"),
                    "status": c.get("current_status")})
    return out


def companies_house_search(http, name: str, key: str) -> list[dict]:
    auth = base64.b64encode(f"{key}:".encode()).decode()
    d = http.get_json("https://api.company-information.service.gov.uk/search/companies?q="
                      f"{urllib.parse.quote(name)}&items_per_page=5", {"Authorization": f"Basic {auth}"})
    return [{"name": i.get("title"), "number": i.get("company_number"), "status": i.get("company_status"),
             "incorporated": i.get("date_of_creation")} for i in (d or {}).get("items", [])]


def opensanctions_match(http, name: str, key: str) -> list[dict]:
    d = http.post_json("https://api.opensanctions.org/match/default",
                       {"queries": {"q1": {"schema": "Company", "properties": {"name": [name]}}}},
                       {"Authorization": f"ApiKey {key}"})
    res = (((d or {}).get("responses") or {}).get("q1") or {}).get("results", [])
    return [{"name": r.get("caption"), "score": r.get("score"), "datasets": r.get("datasets", [])}
            for r in res if r.get("match")]


def rdap_domain(http, domain: str, now: Optional[datetime] = None) -> dict:
    now = now or datetime.now(timezone.utc)
    d = http.get_json(f"https://rdap.org/domain/{domain}")
    if not isinstance(d, dict):
        return {"domain": domain, "available": False}
    ev = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])}
    reg = ev.get("registration")
    age = None
    if reg:
        try:
            dt = datetime.fromisoformat(reg.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            age = (now - dt).days
        except ValueError:
            pass
    registrar = None
    for e in d.get("entities", []):
        if "registrar" in e.get("roles", []):
            vc = (e.get("vcardArray") or [None, []])[1]
            registrar = next((x[3] for x in vc if x and x[0] == "fn"), None)
    return {"domain": domain, "available": True, "registered": reg, "age_days": age,
            "expires": ev.get("expiration"), "changed": ev.get("last changed"), "registrar": registrar,
            "nameservers": [n.get("ldhName") for n in d.get("nameservers", [])]}


# --------------------------------------------------------------------------- orchestrazione
def lookup_entity(http, name: Optional[str] = None, country: Optional[str] = None, vat: Optional[str] = None,
                  declared_name: Optional[str] = None, env: Optional[dict] = None) -> tuple[dict, list[Finding]]:
    import os
    env = env if env is not None else os.environ
    res: dict = {"query": {"name": name, "country": country, "vat": vat}, "sources": []}
    fs: list[Finding] = []
    cc, num = parse_vat(vat, country)
    ref_country = registries.normalize_country(country) or registries.country_from_vat(vat)
    if ref_country:
        res["country"] = ref_country
    digits = re.sub(r"\D", "", vat or "")
    if (ref_country == "BR" or (not ref_country and len(digits) == 14 and not (vat or "")[:2].isalpha())) \
            and len(digits) == 14:
        res["country"] = ref_country = "BR"
        cj = cnpj_lookup(http, digits)
        res["cnpj"] = cj
        if cj:
            res["sources"].append("BrasilAPI (CNPJ)")
            st = (cj.get("status") or "").upper()
            if st and st != "ATIVA":
                fs.append(Finding("ENT_CNPJ_INACTIVE", "high", "high", "fact", "entity", "BrasilAPI (CNPJ)",
                                  {"status": cj.get("status"), "name": cj.get("name") or "n/d"}))
            if declared_name or name:
                ref = declared_name or name
                if cj.get("name") and name_similarity(ref, cj["name"]) < 0.5:
                    fs.append(Finding("ENT_NAME_MISMATCH", "medium", "medium", "interpretation", "entity",
                                      "BrasilAPI (CNPJ)", {"declared": ref, "registered": cj["name"]}))
        else:
            fs.append(Finding("ENT_CNPJ_NOT_FOUND", "medium", "medium", "fact", "entity", "BrasilAPI (CNPJ)",
                              {"cnpj": digits}))
    if cc and num and cc in EU_VIES:
        v = vies_check(http, cc, num)
        res["vies"] = v
        if v:
            res["sources"].append("VIES")
            if v["valid"]:
                fs.append(Finding("ENT_VAT_OK", "info", "high", "fact", "entity", "VIES",
                                  {"vat": f"{cc}{num}", "name": v["name"] or "n/d"}))
                ref = declared_name or name
                if ref and v["name"] and name_similarity(ref, v["name"]) < 0.5:
                    fs.append(Finding("ENT_NAME_MISMATCH", "medium", "medium", "interpretation", "entity",
                                      "VIES", {"declared": ref, "registered": v["name"]}))
            else:
                fs.append(Finding("ENT_VAT_INVALID", "high", "medium", "fact", "entity", "VIES",
                                  {"vat": f"{cc}{num}"}))
    if ref_country in registries.OFFSHORE_FREQUENT:
        fs.append(Finding("ENT_OFFSHORE_JURISDICTION", "medium", "low", "interpretation", "entity",
                          "Dichiarazione del sito / analista", {"country": ref_country}))
    res["verification_sources"] = registries.verification_sources(ref_country)
    if name:
        g = gleif_search(http, name)
        res["gleif"] = g
        res["sources"].append("GLEIF")
        if not g:
            fs.append(Finding("ENT_LEI_NOT_FOUND", "info", "low", "limit", "entity", "GLEIF", {"name": name}))
        if env.get("OPENCORPORATES_API_KEY"):
            res["opencorporates"] = opencorporates_search(http, name, env["OPENCORPORATES_API_KEY"], country)
            res["sources"].append("OpenCorporates")
        if env.get("COMPANIES_HOUSE_KEY") and (not country or country.upper() in ("GB", "UK")):
            res["companies_house"] = companies_house_search(http, name, env["COMPANIES_HOUSE_KEY"])
            res["sources"].append("Companies House (UK)")
        if env.get("OPENSANCTIONS_API_KEY"):
            m = opensanctions_match(http, name, env["OPENSANCTIONS_API_KEY"])
            res["opensanctions"] = m
            res["sources"].append("OpenSanctions")
            if m:
                fs.append(Finding("ENT_SANCTION_MATCH", "critical", "medium", "interpretation", "entity",
                                  "OpenSanctions", {"count": len(m), "name": name,
                                                    "score": max(x.get("score") or 0 for x in m)}))
    return res, fs


def domain_findings(dom: dict) -> list[Finding]:
    if not dom.get("available"):
        return [Finding("DOM_RDAP_UNAVAILABLE", "info", "low", "limit", "domain", "RDAP",
                        {"domain": dom.get("domain", "")})]
    age = dom.get("age_days")
    if age is None:
        return []
    if age < 30:
        sev = "high"
    elif age < 180:
        sev = "medium"
    elif age < 365:
        sev = "low"
    else:
        return []
    return [Finding("DOM_YOUNG", sev, "high", "fact", "domain", "RDAP",
                    {"date": (dom.get("registered") or "")[:10], "days": age})]


def incorporation_findings(incorporated: Optional[str], domain_registered: Optional[str],
                           now: Optional[date] = None) -> list[Finding]:
    """`incorporated` = data di costituzione letta dal registro ufficiale (YYYY-MM-DD), fornita dall'analista."""
    if not incorporated:
        return []
    now = now or date.today()
    inc = date.fromisoformat(incorporated[:10])
    out = []
    days = (now - inc).days
    if days < 365:
        out.append(Finding("ENT_RECENT_INCORP", "medium", "high", "fact", "entity", "Registro (da analista)",
                           {"date": inc.isoformat(), "days": days}))
    if domain_registered:
        dd = date.fromisoformat(domain_registered[:10])
        if dd < inc:
            out.append(Finding("ENT_DOMAIN_BEFORE_INCORP", "medium", "medium-high", "fact", "entity",
                               "RDAP + registro", {"domain_date": dd.isoformat(), "inc_date": inc.isoformat()}))
    return out
