"""Scenario dimostrativo OFFLINE con dati interamente sintetici (nessun indirizzo, società o persona reale).

Riproduce la struttura di un caso tipico di falso arbitraggio crypto: sito con operazioni generate nel browser,
rendimenti incoerenti, società recente con oggetto sociale in contrasto, fondi inoltrati a un wallet collector.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone

from .case import build_case
from .chains import EVM_CHAINS, TRANSFER_TOPIC, Blocklists
from .fakehttp import FakeHttp
from .util import Response

SITE = "https://arbitrage-demo.example"
T0 = 1_790_000_000          # istante del prelievo (sintetico)
AMOUNT = 1500.99


def addr(seed: str) -> str:
    return "0x" + hashlib.sha256(seed.encode()).hexdigest()[:40]


EXCH, WA, WB, WC = addr("demo-exchange"), addr("demo-wallet-A"), addr("demo-wallet-B"), addr("demo-wallet-C")
WD = addr("demo-endpoint-wallet")          # compare solo in /api/finance, non nella pagina
TX = "0x" + hashlib.sha256(b"demo-tx").hexdigest()
TX2 = "0x" + hashlib.sha256(b"demo-tx-2").hexdigest()
TX3 = "0x" + hashlib.sha256(b"demo-tx-3").hexdigest()
NONCE = {WA.lower(): 7, WB.lower(): 1, WC.lower(): 99_677}
BNB = {WA.lower(): 0.1069, WB.lower(): 0.0000016, WC.lower(): 0.382}
USDT = {WA.lower(): 0.00003, WB.lower(): 0.0, WC.lower(): 21_975.237}
BSC_USDT = EVM_CHAINS["bsc"]["usdt"][0]

HTML = f"""<!doctype html><html><head><title>Arbitrage Demo</title></head><body>
<h1>Crypto arbitrage, up to 5% monthly</h1>
<p>Sign up and earn 1.2% daily on your balance. Referral bonus: 7% on your direct invites. Limited spots left!</p>
<p>Deposit USDT (BEP20) to: {WA}</p>
<p>Guaranteed profits, risk-free.</p>
<p>(c) 2026 DEMO CAPITAL, UNIPESSOAL LDA - NIPC 500000000</p>
<h2>Recent Arbitration deals</h2><div id="deals"></div>
<script src="/assets/js/get_arbitration.js"></script>
</body></html>"""

JS = """
fetch('/api/wallet');
function gen(){
  var amount = Math.floor(Math.random()*1450)+1550;
  var spread = (Math.random()*0.0015)+0.001;
  var profit = amount * spread;
  var from_exchange = exchanges[Math.floor(Math.random()*exchanges.length)];
  var to_exchange = exchanges[Math.floor(Math.random()*exchanges.length)];
  $.ajax({type:'POST', url:'data.php', data:{pair:pair, buy:buy, sold:sold, amount:amount, profit:profit, spread:spread}});
}
setInterval(gen, 90000);
$.get('/api/finance', function(d){ $('#addr').text(d.deposit_address); });
$.post('/api/logout', {});
setInterval(function(){ $.get('get_last_deal.php', function(d){ render(d); }); }, 30000);
"""


def _rpc_bsc(method: str, params: list):
    if method == "eth_getTransactionReceipt":
        if params[0].lower() != TX:
            return None
        amt = hex(int(AMOUNT * 10 ** 18))
        return {"blockNumber": "0x76b5c00", "status": "0x1", "logs": [{
            "address": BSC_USDT, "topics": [TRANSFER_TOPIC, "0x" + EXCH[2:].rjust(64, "0"),
                                            "0x" + WA[2:].rjust(64, "0")], "data": amt}]}
    if method == "eth_getBlockByNumber":
        return {"timestamp": hex(T0)}
    if method == "eth_getCode":
        return "0x"
    if method == "eth_getTransactionCount":
        return hex(NONCE.get(params[0].lower(), 0))
    if method == "eth_getBalance":
        return hex(int(BNB.get(params[0].lower(), 0) * 1e18))
    if method == "eth_blockNumber":
        return hex(124_308_534)
    if method == "eth_call":
        a = "0x" + params[0]["data"][-40:]
        if params[0]["to"].lower() == BSC_USDT.lower():
            return hex(int(USDT.get(a.lower(), 0) * 10 ** 18))
        return "0x0"
    return None


def _tokentx(url: str):
    def row(frm, to, ts, h, val=AMOUNT):
        return {"from": frm, "to": to, "timeStamp": str(ts), "hash": h, "tokenDecimal": "18",
                "value": str(int(val * 10 ** 18))}
    if f"address={WA}" in url:
        return {"status": "1", "result": [row(EXCH, WA, T0, TX), row(WA, WB, T0 + 2400, TX2)]}
    if f"address={WB}" in url:
        return {"status": "1", "result": [row(WA, WB, T0 + 2400, TX2), row(WB, WC, T0 + 2400 + 454, TX3)]}
    return {"status": "0", "result": []}


def build_fake_http() -> FakeHttp:
    h = FakeHttp()
    h.add(SITE + "/assets/js/get_arbitration.js", JS, headers={"access-control-allow-origin": "*",
                                                                  "content-type": "application/javascript"})
    h.add(SITE + "/", HTML, headers={"server": "Apache", "x-powered-by": "PHP/7.2.34"},
          cookies=["PHPSESSID=abc; path=/; HttpOnly"])
    h.add(SITE, HTML, headers={"server": "Apache", "x-powered-by": "PHP/7.2.34"},
          cookies=["PHPSESSID=abc; path=/; HttpOnly"])
    h.add(SITE + "/api/finance", {"coin": "USDT", "network": "Ethereum", "deposit_address": WD},
          headers={"content-type": "application/json"})
    h.add(SITE + "/get_last_deal.php", [{"pair": "BTC/USDT", "amount": 1800, "profit": 2.7}],
          headers={"content-type": "application/json"})
    h.add(SITE + "/api/wallet", "Sign in to continue", status=401)
    h.add("https://rdap.org/domain/arbitrage-demo.example", {
        "events": [{"eventAction": "registration", "eventDate": "2026-06-23T10:00:00Z"}],
        "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Demo Registrar Inc."]]]}],
        "nameservers": [{"ldhName": "ns1.demo-hosting.example"}, {"ldhName": "ns2.demo-hosting.example"}]})
    h.add("https://ec.europa.eu/taxation_customs/vies/rest-api/ms/PT/vat/500000000",
          {"isValid": True, "name": "DEMO CAPITAL, UNIPESSOAL LDA", "address": "---"})
    h.add("https://api.gleif.org/api/v1/lei-records", {"data": []}, exact=False)
    h.routes.append(("https://api.etherscan.io/v2/api",
                     lambda url: Response(url, 200, {}, json.dumps(_tokentx(url)).encode(), [])))
    h.add_rpc(EVM_CHAINS["bsc"]["rpc"][0], _rpc_bsc)
    return h


def build_demo_case(lang: str = "it") -> dict:
    http = build_fake_http()
    tmpdir = tempfile.mkdtemp()
    ev_path = os.path.join(tmpdir, "screenshot_originale_demo.png")
    with open(ev_path, "wb") as f:
        f.write(b"synthetic screenshot bytes")
    bl = Blocklists()
    bl.sets["Lista di esempio (sintetica)"] = {addr("some-other-address").lower()}
    case = build_case(
        http, url=SITE, tx=TX, tx_chain="bsc", country="PT", incorporated="2026-07-01", evidence=(ev_path,),
        etherscan_key="demo", blocklists=bl, lang=lang,
        meta={"target": "arbitrage-demo.example", "analyst": "osintr-ext (demo)", "case_ref": "DEMO-001",
              "reporter_country": "IT", "redact": True, "report_version": "1.0"},
        now=datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc))
    case["manual_findings"].append({
        "code": "MANUAL", "severity": "high", "confidence": "high", "kind": "fact", "area": "manual",
        "basis": "Account esaminato dall'analista",
        "title": "Prelievo non disponibile nonostante il maturato",
        "detail": "Il pannello mostra guadagni maturati ma un saldo prelevabile pari a zero; l'indicatore dei "
                  "giorni residui è negativo."})
    os.unlink(ev_path)
    os.rmdir(tmpdir)
    return case


def build_demo_scan() -> dict:
    """Dati nel formato prodotto da osint_recon.scan_domain, coerenti con il sito sintetico di build_fake_http()."""
    return {
        "target": "arbitrage-demo.example", "type": "domain", "scanned_at": "2026-09-27T12:00:00+00:00",
        "ip_info": {"status": "success", "country": "Netherlands", "regionName": "North Holland", "city": "Amsterdam",
                    "isp": "Demo Hosting BV", "org": "Demo Hosting", "as": "AS64500 Demo Hosting", "resolved_ip": "203.0.113.10"},
        "reverse_dns": {"ptr_hostname": "srv10.demo-hosting.example"},
        "ssl": {"issuer": {"organizationName": "Let's Encrypt"}, "not_before": "Jun 24 08:00:00 2026 GMT",
                "not_after": "Sep 22 08:00:00 2026 GMT", "san_domains": ["arbitrage-demo.example"]},
        "subdomains": {"subdomains": ["arbitrage-demo.example", "api.arbitrage-demo.example", "pay.arbitrage-demo.example"],
                       "count": 3},
        "wayback": {"latest_snapshot": {}, "sample_history": [], "has_any_snapshot": False},
        "similar_domains": {"permutations_checked": 25, "registered_found": [
            {"domain": "arbitrage-demo.net", "resolved_ip": "203.0.113.10"},
            {"domain": "arbitrage-demo-support.com", "resolved_ip": "198.51.100.7"}]},
        "reverse_ip": {"co_hosted_domains": ["arbitrage-demo.net", "other-demo.example"], "count": 2},
        "abuseipdb": {"abuse_confidence_score": 40, "total_reports": 12},
        "exposed_ports": {"found": True, "open_ports": [22, 80, 443, 3306], "cpes": ["cpe:/a:php:php:7.2.34"],
                          "known_vulnerabilities": [], "hostnames": [], "tags": []},
        "known_vulnerabilities": {"signals_checked": ["PHP 7.2.34"], "total_cves_found": 5},
        "http_fingerprint": {"emails_found": ["support@arbitrage-demo.example"],
                             "crypto_addresses_found": {"ethereum": [WA]}},
        "additional_pages": {},
        "discovered_contacts_analysis": {"emails": {"support@arbitrage-demo.example": {
            "gravatar": {}, "breaches": {"found_in_breaches": True, "breach_count": 3, "breach_names": ["A", "B", "C"]}}},
            "phones": {}},
        "discovered_company_analysis": {"piva": {"PT500000000": {
            "registry": {"valid": True, "name": "DEMO CAPITAL, UNIPESSOAL LDA"},
            "sanctions_screening": {"match_count": 1, "matches": [{"name": "DEMO CAPITAL TRADING", "source": "SDN"}]}}}},
        "darkweb": {"count": 2, "results": []},
    }
