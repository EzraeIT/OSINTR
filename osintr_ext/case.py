"""Orchestrazione: costruisce un 'caso' (dict JSON-serializzabile) da sito, indirizzi, tx ed entità."""
from __future__ import annotations

import os
import urllib.parse
from datetime import datetime, timezone
from typing import Callable, Optional

from . import chains, entity, registries, webscan
from .addresses import classify
from .util import VERSION, Finding, assess, fmt_num, sha256_file, short


def _domain_of(url: str) -> str:
    host = urllib.parse.urlparse(url if "://" in url else "https://" + url).netloc.lower()
    return host.removeprefix("www.")


def _wallet_entry(label: str, role: str, addr: str, snap: Optional[dict], reading: str = "") -> dict:
    return {"label": label, "role": role, "address": addr, "snapshot": snap, "reading": reading}


def _reading(snap: Optional[dict], lang: str = "it") -> str:
    if not snap:
        return ""
    t = (lambda it, en: it if lang == "it" else en)
    if snap["chain"] in chains.EVM_CHAINS:
        if snap["type"] == "contract":
            return t("Smart contract (non EOA)", "Smart contract (not an EOA)")
        n, tok = snap["nonce"], sum(snap["tokens"].values())
        if n >= 1000:
            return t("Indirizzo ad altissima attività, compatibile con collector/pass-through",
                     "Very high-activity address, consistent with collector/pass-through")
        if n <= 10 and tok < 1:
            return t("Wallet di transito svuotato / poco usato", "Drained or lightly used transit wallet")
        return t("EOA con attività moderata", "EOA with moderate activity")
    if snap["chain"] in ("btc", "ltc", "doge"):
        return t(f"{snap['tx_count']} transazioni", f"{snap['tx_count']} transactions")
    if snap["chain"] == "sol":
        n = snap.get("tx_sampled", 0)
        suffix = "+" if snap.get("sig_cap_hit") else ""
        return t(f"{n}{suffix} firme recenti", f"{n}{suffix} recent signatures")
    return ""


def build_case(http, *, url: Optional[str] = None, addresses: tuple = (), tx: Optional[str] = None,
               tx_chain: str = "bsc", company: Optional[str] = None, country: Optional[str] = None,
               vat: Optional[str] = None, incorporated: Optional[str] = None, evidence: tuple = (),
               meta: Optional[dict] = None, etherscan_key: Optional[str] = None,
               blocklists: Optional[chains.Blocklists] = None, save_dir: Optional[str] = None,
               max_addresses: int = 8, now: Optional[datetime] = None, lang: str = "it",
               discover: bool = True, progress: Optional["Callable[[str], None]"] = None) -> dict:
    """`progress`, se passato, viene richiamato con un messaggio breve prima di ogni fase lenta (scansione del
    sito/endpoint, verifica società, interrogazioni on-chain): serve solo a dare un segnale che lo strumento sta
    ancora lavorando durante fasi senza altro output, non è richiesto per l'uso normale della funzione."""
    now = now or datetime.now(timezone.utc)
    _p = progress or (lambda _msg: None)
    meta = dict(meta or {})
    findings: list[Finding] = []
    sources: list[str] = []
    case: dict = {"findings": [], "manual_findings": [], "wallets": [], "flow": None, "victim_tx": None,
                  "site": None, "domain": None, "entity": None, "evidence": [], "sources_used": sources}

    domain = _domain_of(url) if url else ""
    meta.setdefault("target", domain or company or (addresses[0] if addresses else "target"))
    meta.update({"target_url": url or "", "analysis_date": now.date().isoformat(), "timezone": "UTC",
                 "tool_version": VERSION, "lang": lang})
    case["meta"] = meta

    # ---- sito
    found_addrs: list[dict] = []
    declared_name = None
    country_inferred = False
    if url:
        _p("Analisi del sito e ricerca degli endpoint citati dal codice (può richiedere qualche minuto)..."
           if lang == "it" else "Analysing the site and the endpoints it references (this can take a few minutes)...")
        scan = webscan.scan_site(http, url, save_dir=save_dir, now=now, discover_enabled=discover, progress=_p)
        case["site"] = scan
        sources.append("Analisi statica passiva del frontend pubblico (HTML, JavaScript, header HTTP)")
        findings += webscan.site_findings(scan)
        found_addrs = scan.get("addresses", [])
        names = scan.get("company_mentions", {}).get("names", [])
        declared_name = names[0] if names else None
        ids = scan.get("company_mentions", {}).get("ids", [])
        if not vat and ids:
            vat = next((i for i in ids if i[:2].isalpha()), None)
            if not vat and ids:
                # numero senza prefisso paese: se abbiamo un paese esplicito lo usiamo; altrimenti,
                # SOLO per poter verificare il numero su un registro, usiamo un indizio debole dal sito
                # stesso (lingua della pagina/URL) - mai inventato, e segnalato come inferenza nel caso/PDF.
                vat = ids[0]
                if not country:
                    hint = scan.get("locale_hint")
                    if hint:
                        country, country_inferred = hint["country"], True
        dom = entity.rdap_domain(http, domain, now)
        case["domain"] = dom
        sources.append("RDAP (data di registrazione del dominio)")
        findings += entity.domain_findings(dom)

    # ---- entità
    if not country and not vat and domain:
        country = registries.country_from_domain(domain) or None   # solo per indicare le fonti ufficiali
    if company or vat or declared_name or country:
        _p("Verifica società (registri ufficiali) e dell'indirizzo dichiarato..." if lang == "it" else
           "Checking the company against official registries and verifying the declared address...")
        ent, efs = entity.lookup_entity(http, name=company or declared_name, country=country, vat=vat,
                                        declared_name=declared_name)
        if ent and country_inferred:
            ent["country_inferred_from"] = "Lingua/URL del sito (indizio debole, non dichiarazione esplicita)"
        case["entity"] = ent
        findings += efs
        sources += [f"Registri/anagrafiche aperte: {', '.join(ent['sources'])}"] if ent["sources"] else []
    findings += entity.incorporation_findings(
        incorporated, (case["domain"] or {}).get("registered"), now.date())

    # ---- tx della vittima + tracciamento
    deposit_addrs: list[str] = []
    if tx:
        _p("Decodifica della transazione e tracciamento dei fondi..." if lang == "it" else
           "Decoding the transaction and tracing the funds...")
        d = chains.decode_transfer_tx(http, tx_chain, tx)
        sources.append(f"JSON-RPC {tx_chain.upper()} (receipt, log ERC-20, saldi, nonce, bytecode)")
        if d:
            case["victim_tx"] = d
            deposit_addrs.append(d["to"])
            hops = []
            if etherscan_key:
                hops = chains.trace_forward(http, tx_chain, d["to"], d["token"], etherscan_key, d["amount"],
                                            d.get("timestamp") or 0)
                sources.append("API explorer compatibile Etherscan v2 (trasferimenti token)")
            nodes = [{"label": "ORIGINE" if lang == "it" else "SOURCE",
                      "role": "exchange / wallet" if lang == "en" else "exchange / wallet",
                      "address": d["from"]},
                     {"label": "WALLET A", "role": "destinatario" if lang == "it" else "recipient",
                      "address": d["to"]}]
            edges = [{"amount": d["amount"], "token": d["token"], "delay_s": None}]
            for i, h in enumerate(hops):
                nodes.append({"label": f"WALLET {chr(66 + i)}", "role": "", "address": h["to"]})
                edges.append({"amount": h["amount"], "token": h["token"], "delay_s": h["delay_s"]})
                deposit_addrs.append(h["to"])
            case["flow"] = {"nodes": nodes, "edges": edges, "hops": hops, "traced": bool(etherscan_key)}
            if hops and all(h.get("matched_amount") and h.get("to_type") == "EOA" for h in hops):
                total_min = round(sum(h["delay_s"] or 0 for h in hops) / 60)
                findings.append(Finding("ONC_PASSTHROUGH_FLOW", "critical", "high", "fact", "onchain",
                                        "Ledger " + tx_chain.upper(),
                                        {"amount": fmt_num(d["amount"], 2, lang), "token": d["token"],
                                         "hops": len(hops), "minutes": total_min}))

    # ---- indirizzi
    todo: list[tuple[str, str, list]] = []
    seen = set()
    for a in deposit_addrs:
        todo.append((a, "evm", [tx_chain]))
    for a in addresses:
        fam = classify(a)
        if fam:
            todo.append((a, fam, []))
    for a in found_addrs:
        todo.append((a["address"], a["family"], a.get("hints", [])))
    uniq = []
    for a, fam, hints in todo:
        k = a.lower()
        if k not in seen:
            seen.add(k)
            uniq.append((a, fam, hints))
    if found_addrs:
        fams = sorted({a["family"] for a in found_addrs})
        findings.append(Finding("ONC_ADDR_FOUND", "info", "high", "fact", "onchain", "Frontend del sito",
                                {"count": len(found_addrs), "families": ", ".join(fams)}))
    via = [a for a in found_addrs if str(a.get("source", "")).startswith(("endpoint:", "page:"))]
    if via:
        where = sorted({a["source"].split(":", 1)[1] for a in via})
        findings.append(Finding("ONC_ADDR_FROM_ENDPOINT", "info", "high", "fact", "onchain",
                                "Endpoint e pagine citati dal sito (solo GET)",
                                {"count": len(via), "where": ", ".join(where[:4])}))
    if uniq:
        sources.append("Snapshot on-chain: JSON-RPC EVM e Solana, mempool.space (BTC/LTC), BlockCypher (DOGE), TronGrid (TRON)")
    if blocklists and blocklists.sets:
        sources.append("Liste di indirizzi sanzionati/segnalati: " + ", ".join(sorted(blocklists.sets)))

    flow_labels = {n["address"].lower(): n for n in (case["flow"] or {}).get("nodes", [])}
    if uniq:
        _p(f"Controllo on-chain di {min(len(uniq), max_addresses)} indirizzo/i..." if lang == "it" else
           f"Checking {min(len(uniq), max_addresses)} address(es) on-chain...")
    for addr, fam, hints in uniq[:max_addresses]:
        snaps = []
        if fam == "evm":
            snaps = chains.evm_scan(http, addr, hints)
        elif fam in ("btc", "ltc"):
            s = chains.utxo_snapshot(http, fam, addr)
            snaps = [s] if s else []
        elif fam == "doge":
            s = chains.doge_snapshot(http, addr)
            snaps = [s] if s else []
        elif fam == "sol":
            s = chains.solana_snapshot(http, addr)
            snaps = [s] if s else []
        elif fam == "tron":
            s = chains.tron_snapshot(http, addr)
            snaps = [s] if s else []
        node = flow_labels.get(addr.lower())
        label = node["label"].title() if node else short(addr)
        role = node["role"] if node else ("sito" if lang == "it" else "site")
        if not snaps:
            case["wallets"].append(_wallet_entry(label, role, addr, {"chain": fam, "type": "n/d"}, ""))
        for s in snaps:
            case["wallets"].append(_wallet_entry(label, role, addr, s, _reading(s, lang)))
            findings += chains.interpret_snapshot(addr, s, f"Snapshot {s['chain'].upper()}", lang)
        if blocklists:
            findings += chains.list_findings(addr, blocklists.match(addr), "Blocklist")

    # ---- evidenze
    for p in evidence:
        case["evidence"].append({"name": os.path.basename(p), "sha256": sha256_file(p)})
    if case["site"] and case["site"].get("html_sha256"):
        case["evidence"].append({"name": "index.html (acquisito)", "sha256": case["site"]["html_sha256"]})
    for j in (case["site"] or {}).get("js_files", []):
        case["evidence"].append({"name": j["url"].rsplit("/", 1)[-1] or j["url"], "sha256": j["sha256"]})

    _finalize(case, findings, lang)
    return case


def all_findings(case: dict) -> list[Finding]:
    """Finding automatici + manuali (aggiunti dall'analista nel JSON), con ID stabili F01.. / M01.."""
    auto = [Finding.from_dict(d) for d in case.get("findings", [])]
    man = [Finding.from_dict(d) for d in case.get("manual_findings", [])]
    for i, f in enumerate(auto, 1):
        f.id = f.id or f"F{i:02d}"
    for i, f in enumerate(man, 1):
        f.id = f.id or f"M{i:02d}"
    return auto + man


def _finalize(case: dict, findings: list[Finding], lang: str) -> None:
    for i, f in enumerate(findings, 1):
        f.id = f"F{i:02d}"
    case["findings"] = [f.to_dict() for f in findings]
    level, score = assess(all_findings(case))
    case["assessment"] = {"level": level, "score": score}
