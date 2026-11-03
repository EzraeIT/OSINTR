"""Ponte tra i dati di scansione di osint_recon.py (scan_domain) e il caso/rapporto di osintr_ext.

Usa i risultati già raccolti dallo script (CT/sottodomini, Wayback, typosquat, IP, porte, SSL, violazioni,
sanzioni, registri CNPJ/VIES) per:
  - aggiungere finding con codici INF_* alla matrice di rischio;
  - aggiungere al PDF la sezione "Infrastruttura, cronologia e reti collegate" (case["extra_sections"]).
In più riesegue, in modo passivo, le analisi proprie dell'estensione (codice JavaScript, rendimenti, indirizzi
crypto multi-chain, flussi on-chain) e le unisce nello stesso caso.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from .case import _finalize, build_case
from .util import Finding, Http

RISKY_PORTS = {21: "FTP", 23: "Telnet", 445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
               5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB"}


def _d(x) -> dict:
    return x if isinstance(x, dict) else {}


def _l(x) -> list:
    return x if isinstance(x, list) else []


def _ok(x) -> bool:
    """Un blocco di scansione utilizzabile (non errore, non 'skipped')."""
    return isinstance(x, dict) and not x.get("error") and not x.get("skipped")


def _mask_email(e: str) -> str:
    user, _, dom = e.partition("@")
    return (user[:2] + "***@" + dom) if dom else e


# --------------------------------------------------------------------------- estrazione dai dati dello script
def collect_crypto(data: dict) -> list[str]:
    hf, ap = _d(data.get("http_fingerprint")), _d(data.get("additional_pages"))
    out: list[str] = []
    for src in (_d(hf.get("crypto_addresses_found")), _d(ap.get("crypto_found"))):
        for vals in src.values():
            for a in _l(vals):
                if a not in out:
                    out.append(a)
    return out


def company_from_scan(data: dict) -> dict:
    """Primo identificativo societario trovato: {'vat','country','company','incorporated','registry'}."""
    comp = _d(data.get("discovered_company_analysis"))
    for piva, blk in _d(comp.get("piva")).items():
        reg = _d(blk.get("registry"))
        cc = piva[:2].upper()
        return {"vat": piva, "country": cc, "company": reg.get("name"), "incorporated": None, "registry": reg,
                "sanctions": _d(blk.get("sanctions_screening"))}
    for cnpj, blk in _d(comp.get("cnpj")).items():
        reg = _d(blk.get("registry"))
        inc = reg.get("data_inicio_atividade")
        return {"vat": re.sub(r"\D", "", cnpj), "country": "BR", "company": reg.get("razao_social"),
                "incorporated": inc[:10] if isinstance(inc, str) and re.match(r"\d{4}-\d{2}-\d{2}", inc) else None,
                "registry": reg, "sanctions": _d(blk.get("sanctions_screening"))}
    return {}


# --------------------------------------------------------------------------- finding INF_*
def scan_findings(data: dict, lang: str = "it") -> list[Finding]:
    fs: list[Finding] = []
    ip = _d(data.get("ip_info")).get("resolved_ip")

    wb = _d(data.get("wayback"))
    if wb and not wb.get("has_any_snapshot") and "_available_api_error" not in wb and "_cdx_api_error" not in wb:
        fs.append(Finding("INF_NO_WAYBACK", "low", "medium", "fact", "domain", "Wayback Machine / CDX", {}))

    subs = _d(data.get("subdomains"))
    if _ok(subs) and subs.get("count"):
        fs.append(Finding("INF_SUBDOMAINS", "info", "high", "fact", "web", "Certificate Transparency (crt.sh)",
                          {"count": subs["count"]}))

    sim = _d(data.get("similar_domains"))
    reg = [x for x in _l(sim.get("registered_found")) if isinstance(x, dict)]
    if reg:
        names = ", ".join(x.get("domain", "") for x in reg[:4])
        fs.append(Finding("INF_TYPO_REGISTERED", "low", "low", "interpretation", "domain", "Risoluzione DNS delle varianti",
                          {"count": len(reg), "checked": sim.get("permutations_checked", "n/d"), "examples": names}))
        same = [x["domain"] for x in reg if ip and x.get("resolved_ip") == ip]
        if same:
            fs.append(Finding("INF_TYPO_SAME_IP", "medium", "medium", "interpretation", "domain",
                              "Risoluzione DNS delle varianti", {"examples": ", ".join(same[:4])}))

    rip = _d(data.get("reverse_ip"))
    n = rip.get("count") or 0
    if _ok(rip) and 0 < n <= 15:
        fs.append(Finding("INF_RELATED_DOMAINS", "low", "low", "interpretation", "domain", "Reverse IP (HackerTarget)",
                          {"count": n, "examples": ", ".join(_l(rip.get("co_hosted_domains"))[:4])}))

    ab = _d(data.get("abuseipdb"))
    score = ab.get("abuse_confidence_score")
    if _ok(ab) and isinstance(score, (int, float)) and score >= 25:
        fs.append(Finding("INF_ABUSE_IP", "high" if score >= 75 else "medium", "medium", "fact", "web", "AbuseIPDB",
                          {"score": score, "reports": ab.get("total_reports", "n/d")}))

    ports = _d(data.get("exposed_ports"))
    risky = sorted(p for p in _l(ports.get("open_ports")) if p in RISKY_PORTS)
    if risky:
        fs.append(Finding("INF_EXPOSED_PORTS", "low", "medium", "fact", "web", "Shodan InternetDB (passivo)",
                          {"ports": ", ".join(f"{p}/{RISKY_PORTS[p]}" for p in risky)}))

    kv = _d(data.get("known_vulnerabilities"))
    if kv.get("total_cves_found"):
        fs.append(Finding("INF_KNOWN_CVES", "low", "low", "interpretation", "web", "NVD (NIST)",
                          {"count": kv["total_cves_found"], "software": ", ".join(map(str, _l(kv.get("signals_checked"))[:3]))}))

    contacts = _d(data.get("discovered_contacts_analysis"))
    breached = [e for e, blk in _d(contacts.get("emails")).items()
                if _d(_d(blk).get("breaches")).get("found_in_breaches")]
    if breached:
        fs.append(Finding("INF_BREACHED_EMAIL", "info", "medium", "fact", "web", "XposedOrNot",
                          {"count": len(breached), "total": len(_d(contacts.get("emails")))}))

    dw = _d(data.get("darkweb"))
    if _ok(dw) and dw.get("count"):
        fs.append(Finding("INF_DARKWEB_HITS", "low", "low", "fact", "web", "IntelligenceX", {"count": dw["count"]}))

    comp = company_from_scan(data)
    sm = _d(comp.get("sanctions"))
    if sm.get("match_count"):
        srcs = sorted({str(m.get("source")) for m in _l(sm.get("matches")) if isinstance(m, dict)})
        fs.append(Finding("INF_SANCTIONS_NAME", "high", "low", "interpretation", "entity",
                          "Consolidated Screening List (trade.gov)",
                          {"name": comp.get("company") or "n/d", "count": sm["match_count"], "sources": ", ".join(srcs)}))
    return fs


# --------------------------------------------------------------------------- sezioni extra del PDF
def extra_sections(data: dict, lang: str = "it") -> list[dict]:
    it = lang == "it"
    t = (lambda a, b: a if it else b)
    secs: list[dict] = []

    # --- rete / infrastruttura
    rows = []
    ipi = _d(data.get("ip_info"))
    if ipi.get("resolved_ip"):
        loc = ", ".join(x for x in (ipi.get("city"), ipi.get("regionName"), ipi.get("country")) if x)
        rows.append([t("Indirizzo IP", "IP address"), f"{ipi['resolved_ip']}  ({loc or 'n/d'})"])
        rows.append([t("Operatore / ASN", "Provider / ASN"), f"{ipi.get('isp') or ipi.get('org') or 'n/d'}  /  {ipi.get('as') or 'n/d'}"])
    ptr = _d(data.get("reverse_dns")).get("ptr_hostname")
    if ptr:
        rows.append(["PTR", ptr])
    ssl_ = _d(data.get("ssl"))
    if _ok(ssl_) and ssl_.get("not_before"):
        issuer = _d(ssl_.get("issuer")).get("organizationName") or _d(ssl_.get("issuer")).get("commonName") or "n/d"
        rows.append([t("Certificato TLS", "TLS certificate"),
                     f"{issuer}; {t('valido dal', 'valid from')} {ssl_['not_before']} {t('al', 'to')} {ssl_.get('not_after', 'n/d')}; "
                     f"{len(_l(ssl_.get('san_domains')))} SAN"])
    ports = _d(data.get("exposed_ports"))
    if ports.get("found"):
        rows.append([t("Porte note a Shodan", "Ports known to Shodan"), ", ".join(map(str, _l(ports.get("open_ports")))) or "-"])
        if ports.get("cpes"):
            rows.append([t("Software rilevato", "Detected software"), ", ".join(_l(ports["cpes"])[:5])])
    ab = _d(data.get("abuseipdb"))
    if _ok(ab):
        rows.append(["AbuseIPDB", f"{t('punteggio', 'score')} {ab.get('abuse_confidence_score')}, "
                                  f"{ab.get('total_reports')} {t('segnalazioni (90 gg)', 'reports (90 d)')}"])
    if rows:
        secs.append({"title": t("Rete e infrastruttura", "Network and infrastructure"),
                     "cols": [t("Elemento", "Item"), t("Valore", "Value")], "rows": rows,
                     "note": t("Dati passivi da fonti pubbliche; nessuna scansione attiva verso il target.",
                               "Passive data from public sources; no active scanning of the target.")})

    # --- sottodomini + wayback
    rows = []
    subs = _d(data.get("subdomains"))
    if _ok(subs) and subs.get("subdomains"):
        lst = _l(subs["subdomains"])
        rows.append([t("Sottodomini nei log CT", "Subdomains in CT logs"), f"{subs.get('count', len(lst))}: " + ", ".join(lst[:15])
                     + (" ..." if len(lst) > 15 else "")])
    wb = _d(data.get("wayback"))
    if wb:
        snap = _d(wb.get("latest_snapshot")).get("timestamp")
        hist = _l(wb.get("sample_history"))
        if wb.get("has_any_snapshot"):
            rows.append(["Wayback Machine", f"{t('ultimo snapshot', 'latest snapshot')}: {snap or 'n/d'}; "
                                            f"{t('primi snapshot', 'earliest snapshots')}: {', '.join(map(str, hist[:5])) or 'n/d'}"])
        elif "_available_api_error" not in wb and "_cdx_api_error" not in wb:
            rows.append(["Wayback Machine", t("nessuno snapshot storico", "no historical snapshot")])
    if rows:
        secs.append({"title": t("Cronologia e sottodomini", "History and subdomains"),
                     "cols": [t("Fonte", "Source"), t("Esito", "Result")], "rows": rows,
                     "note": t("L'assenza di storico è coerente con un sito recente, ma da sola non prova nulla.",
                               "A missing history fits a recent site, but proves nothing on its own.")})

    # --- reti collegate
    rows = []
    sim = _d(data.get("similar_domains"))
    ip = ipi.get("resolved_ip")
    for x in _l(sim.get("registered_found"))[:10]:
        if isinstance(x, dict):
            rows.append([x.get("domain", ""), f"{x.get('resolved_ip', '')}" +
                         (t("  (stesso IP del target)", "  (same IP as target)") if ip and x.get("resolved_ip") == ip else "")])
    rip = _d(data.get("reverse_ip"))
    if _ok(rip) and rip.get("co_hosted_domains") and (rip.get("count") or 0) <= 15:
        rows.append([t("Altri domini sullo stesso IP", "Other domains on the same IP"),
                     ", ".join(_l(rip["co_hosted_domains"])[:10])])
    if rows:
        secs.append({"title": t("Domini simili e reti collegate", "Lookalike domains and related networks"),
                     "cols": [t("Dominio", "Domain"), "IP / " + t("nota", "note")], "rows": rows,
                     "note": t(f"Varianti controllate: {sim.get('permutations_checked', 'n/d')}. Una variante registrata non prova un "
                               "collegamento: va incrociata con registrant, nameserver e contenuti.",
                               f"Variants checked: {sim.get('permutations_checked', 'n/d')}. A registered variant does not prove a "
                               "link: cross-check registrant, nameservers and content.")})

    # --- contatti, violazioni, sanzioni
    rows = []
    contacts = _d(data.get("discovered_contacts_analysis"))
    for e, blk in _d(contacts.get("emails")).items():
        b = _d(_d(blk).get("breaches"))
        if b.get("error"):
            res = t("controllo non riuscito", "check failed")
        elif b.get("found_in_breaches"):
            res = t(f"presente in {b.get('breach_count')} violazioni", f"found in {b.get('breach_count')} breaches")
        else:
            res = t("non risulta in violazioni note", "not found in known breaches")
        rows.append([_mask_email(e), res])
    comp = company_from_scan(data)
    if comp:
        reg = _d(comp.get("registry"))
        status = reg.get("situacao_cadastral") or ("valida" if reg.get("valid") else None)
        if reg.get("valid") is not None and it:
            status = "valida" if reg.get("valid") else "NON valida"
        elif reg.get("valid") is not None:
            status = "valid" if reg.get("valid") else "NOT valid"
        rows.append([t("Società trovata nel sito", "Company found on the site"),
                     f"{comp.get('company') or 'n/d'} ({comp.get('vat')}), {status or 'n/d'}"])
        sm = _d(comp.get("sanctions"))
        if sm.get("skipped"):
            rows.append([t("Screening sanzioni", "Sanctions screening"), t("non eseguito (chiave API mancante)", "not run (missing API key)")])
        elif "match_count" in sm:
            rows.append([t("Screening sanzioni", "Sanctions screening"),
                         t(f"{sm['match_count']} corrispondenze per nome", f"{sm['match_count']} name matches")])
    dw = _d(data.get("darkweb"))
    if _ok(dw):
        rows.append(["IntelligenceX", t(f"{dw.get('count', 0)} risultati", f"{dw.get('count', 0)} results")])
    if rows:
        secs.append({"title": t("Contatti, società e fonti di leak", "Contacts, company and leak sources"),
                     "cols": [t("Elemento", "Item"), t("Esito", "Result")], "rows": rows,
                     "note": t("Le email sono mascherate nel PDF. Una corrispondenza per nome nelle liste sanzioni può essere un falso positivo.",
                               "Emails are masked in the PDF. A name match in sanctions lists may be a false positive.")})
    return secs


# --------------------------------------------------------------------------- entry point
def case_from_scan(data: dict, http: Optional[Http] = None, *, lang: str = "it", tx: Optional[str] = None,
                   tx_chain: str = "bsc", evidence: tuple = (), meta: Optional[dict] = None,
                   etherscan_key: Optional[str] = None, blocklists=None, save_dir: Optional[str] = None,
                   country: Optional[str] = None, vat: Optional[str] = None, incorporated: Optional[str] = None,
                   now: Optional[datetime] = None, discover: bool = True, progress=None) -> dict:
    """Costruisce il caso forense per un target di tipo dominio, unendo i dati dello script e le analisi dell'estensione."""
    if data.get("type") != "domain":
        raise ValueError("il rapporto PDF forense è disponibile per i target di tipo dominio")
    http = http or Http()
    domain = data["target"]
    comp = company_from_scan(data)
    case = build_case(
        http, url=f"https://{domain}", addresses=tuple(collect_crypto(data)), tx=tx, tx_chain=tx_chain,
        company=comp.get("company"), country=country or comp.get("country"), vat=vat or comp.get("vat"),
        incorporated=incorporated or comp.get("incorporated"), evidence=evidence, meta=meta,
        etherscan_key=etherscan_key, blocklists=blocklists, save_dir=save_dir, now=now, lang=lang,
        discover=discover, progress=progress)
    # unisce i finding dello script a quelli dell'estensione e ricalcola la valutazione
    existing = [Finding.from_dict(f) for f in case["findings"]]
    for f in existing:
        f.id = ""
    merged = existing + scan_findings(data, lang)
    case["sources_used"].append("Dati di scansione osint_recon.py (CT, Wayback, DNS, IP, porte, violazioni, registri)")
    case["extra_sections"] = extra_sections(data, lang)
    case["scan_scanned_at"] = data.get("scanned_at")
    _finalize(case, merged, lang)
    return case
