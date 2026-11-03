"""CLI di osintr_ext.

    python -m osintr_ext case   --url https://sito.example --pdf rapporto.pdf --json caso.json
    python -m osintr_ext addr   0x... bc1... T... <solana> --ofac
    python -m osintr_ext report caso.json --pdf rapporto.pdf --lang en
    python -m osintr_ext selftest --pdf esempio.pdf

Solo fonti pubbliche e interrogazioni passive. Nessuna autenticazione sui siti analizzati.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from . import chains
from .addresses import classify
from .case import all_findings, build_case
from .findings_text import render_finding
from .util import Http, VERSION


def _load_report():
    """Importa il generatore PDF solo quando serve, con un messaggio chiaro se reportlab non e' utilizzabile."""
    try:
        from . import report
        return report
    except ImportError as e:
        print(f"! Generatore PDF non disponibile: {e}\n"
              "  Installa una versione compatibile:  pip install \"reportlab<5\"   "
              "(reportlab 5.x richiede Python 3.10+)", file=sys.stderr)
        return None


def _load_blocklists(http, args) -> chains.Blocklists | None:
    bl = chains.Blocklists()
    ok = False
    if getattr(args, "ofac", False):
        ok = bl.load_ofac(http, cache_dir=args.cache_dir) or ok
        if not ok:
            print("! lista OFAC non scaricabile: controlli sanzioni indirizzi saltati", file=sys.stderr)
    for p in getattr(args, "blocklist", None) or []:
        bl.load_file(p)
        ok = True
    return bl if ok else None


def _print_findings(case: dict, lang: str) -> None:
    from .util import SEV_ORDER
    fs = sorted(all_findings(case), key=lambda f: (-SEV_ORDER[f.severity], f.id))
    lvl = case["assessment"]
    print(f"\nValutazione: {lvl['level'].upper()}  (punteggio {lvl['score']})")
    for f in fs:
        t, _ = render_finding(f, lang)
        print(f"  [{f.severity:<8}] {f.id}  {t}")


def cmd_case(args) -> int:
    http = Http(delay=args.delay)
    if not (args.url or args.address or args.tx or args.company or args.vat):
        print("Serve almeno uno tra --url, --address, --tx, --company, --vat", file=sys.stderr)
        return 2
    meta = {"analyst": args.analyst, "case_ref": args.case_ref, "reporter_country": args.reporter_country,
            "redact": not args.no_redact, "report_version": "1.0"}
    meta = {k: v for k, v in meta.items() if v not in (None, "")}
    case = build_case(
        http, url=args.url, addresses=tuple(args.address or ()), tx=args.tx, tx_chain=args.tx_chain,
        company=args.company, country=args.country, vat=args.vat, incorporated=args.incorporated,
        evidence=tuple(args.evidence or ()), meta=meta, lang=args.lang,
        etherscan_key=args.etherscan_key or os.environ.get("ETHERSCAN_API_KEY"),
        blocklists=_load_blocklists(http, args), save_dir=args.save_dir, max_addresses=args.max_addresses,
        discover=not args.no_discover)
    out_json = args.json or f"caso_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(case, f, ensure_ascii=False, indent=2)
    print(f"Caso salvato: {out_json}")
    eps = (case["site"].get("endpoints") or []) + (case["site"].get("pages") or [])
    if eps:
        print(f"\nEndpoint/pagine esaminati: {len(eps)}  (scartati per le regole di sicurezza: "
              f"{case['site'].get('endpoints_skipped', 0)})")
        for e in eps:
            flag = " [richiede login]" if e.get("auth_required") else ""
            cats = f"  -> {', '.join(e['categories'])}" if e.get("categories") else ""
            addrs = f"  indirizzi: {', '.join(e['addresses'])}" if e.get("addresses") else ""
            print(f"  [{e.get('status', '-')}] {e['url']}{flag}{cats}{addrs}")
    _print_findings(case, args.lang)
    if args.pdf:
        report = _load_report()
        if report is None:
            return 3
        report.render(case, args.pdf, lang=args.lang, redact=not args.no_redact)
        print(f"\nRapporto PDF: {args.pdf}")
    return 0


def cmd_addr(args) -> int:
    http = Http(delay=args.delay)
    bl = _load_blocklists(http, args)
    from .util import Finding
    rc = 0
    for a in args.addresses:
        fam = classify(a)
        if not fam:
            print(f"{a}: formato non riconosciuto (EVM, BTC, LTC, DOGE, TRON, Solana)")
            rc = 1
            continue
        snaps = []
        if fam == "evm":
            snaps = chains.evm_scan(http, a)
        elif fam in ("btc", "ltc"):
            snaps = [s for s in [chains.utxo_snapshot(http, fam, a)] if s]
        elif fam == "doge":
            snaps = [s for s in [chains.doge_snapshot(http, a)] if s]
        elif fam == "tron":
            snaps = [s for s in [chains.tron_snapshot(http, a)] if s]
        elif fam == "sol":
            snaps = [s for s in [chains.solana_snapshot(http, a)] if s]
        print(f"\n{a}  [{fam}]")
        fs: list[Finding] = []
        if not snaps:
            print("  nessun dato (indirizzo inattivo o fonte non raggiungibile)")
        for s in snaps:
            bal = ", ".join(f"{v:,.2f} {k}" for k, v in (s.get("tokens") or {}).items() if v) or "0 token"
            extra = f"nonce {s['nonce']}" if "nonce" in s else f"tx {s.get('tx_count', s.get('tx_sampled', '?'))}"
            print(f"  {s['chain']:<9} {s['type']:<14} {extra:<12} {s.get('native', s.get('balance', 0)):.4f} "
                  f"{s.get('native_symbol', '')}  {bal}")
            fs += chains.interpret_snapshot(a, s, f"Snapshot {s['chain'].upper()}")
        if bl:
            m = bl.match(a)
            fs += chains.list_findings(a, m, "Blocklist")
            if m:
                print(f"  ! presente in: {', '.join(m)}")
        for f in fs:
            t, d = render_finding(f, args.lang)
            print(f"  [{f.severity}] {t}: {d}")
    return rc


def cmd_report(args) -> int:
    with open(args.case_json, encoding="utf-8") as f:
        case = json.load(f)
    report = _load_report()
    if report is None:
        return 3
    out = args.pdf or os.path.splitext(args.case_json)[0] + ".pdf"
    report.render(case, out, lang=args.lang, redact=not args.no_redact)
    print(f"Rapporto PDF: {out}")
    return 0


def cmd_selftest(args) -> int:
    from .demo import build_demo_case
    report = _load_report()
    if report is None:
        return 3
    case = build_demo_case(lang=args.lang)
    out = args.pdf or "esempio_rapporto.pdf"
    report.render(case, out, lang=args.lang, redact=True)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(case, f, ensure_ascii=False, indent=2)
    print(f"Rapporto di esempio (dati sintetici): {out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="osintr_ext", description=f"osintr-ext {VERSION}: analisi passiva di siti, "
                                 "indirizzi crypto e società, con rapporto PDF tecnico-forense.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--lang", choices=["it", "en"], default="it")
        p.add_argument("--delay", type=float, default=0.4, help="pausa minima tra richieste allo stesso host (s)")
        p.add_argument("--ofac", action="store_true", help="scarica/usa la lista OFAC SDN per gli indirizzi")
        p.add_argument("--blocklist", action="append", metavar="FILE", help="file con indirizzi segnalati (uno per riga)")
        p.add_argument("--cache-dir", default=".osintr_cache")

    c = sub.add_parser("case", help="costruisce un caso completo e (opz.) il rapporto PDF")
    common(c)
    c.add_argument("--url", help="sito da analizzare (analisi statica passiva)")
    c.add_argument("--address", action="append", help="indirizzo crypto da controllare (ripetibile)")
    c.add_argument("--tx", help="hash della transazione EVM del prelievo/versamento")
    c.add_argument("--tx-chain", default="bsc", choices=sorted(chains.EVM_CHAINS))
    c.add_argument("--company", help="ragione sociale dichiarata")
    c.add_argument("--country", help="paese della società (ISO 3166-1 alpha-2, es. PT, BR, US)")
    c.add_argument("--vat", help="partita IVA / NIF / CNPJ / numero di registrazione")
    c.add_argument("--incorporated", help="data di costituzione dal registro ufficiale (YYYY-MM-DD)")
    c.add_argument("--evidence", action="append", metavar="FILE", help="file di prova da hashare (SHA-256)")
    c.add_argument("--etherscan-key", help="chiave API Etherscan v2 per tracciare i passaggi successivi")
    c.add_argument("--save-dir", help="cartella dove salvare HTML/JS acquisiti")
    c.add_argument("--max-addresses", type=int, default=8)
    c.add_argument("--no-discover", action="store_true",
                   help="non leggere gli endpoint e le pagine citati dal sito (meno richieste, ma meno indirizzi trovati)")
    c.add_argument("--analyst")
    c.add_argument("--case-ref")
    c.add_argument("--reporter-country", help="paese di chi segnala (per autorità competenti), es. IT")
    c.add_argument("--no-redact", action="store_true", help="NON abbreviare indirizzi/TxID nel PDF (uso riservato)")
    c.add_argument("--json", help="file JSON di output del caso")
    c.add_argument("--pdf", help="file PDF del rapporto")
    c.set_defaults(fn=cmd_case)

    a = sub.add_parser("addr", help="controllo rapido di uno o più indirizzi crypto")
    common(a)
    a.add_argument("addresses", nargs="+")
    a.set_defaults(fn=cmd_addr)

    r = sub.add_parser("report", help="rigenera il PDF da un caso JSON (anche modificato a mano)")
    r.add_argument("case_json")
    r.add_argument("--pdf")
    r.add_argument("--lang", choices=["it", "en"])
    r.add_argument("--no-redact", action="store_true")
    r.set_defaults(fn=cmd_report)

    t = sub.add_parser("selftest", help="genera un rapporto di esempio con dati sintetici (offline)")
    t.add_argument("--pdf")
    t.add_argument("--json")
    t.add_argument("--lang", choices=["it", "en"], default="it")
    t.set_defaults(fn=cmd_selftest)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
