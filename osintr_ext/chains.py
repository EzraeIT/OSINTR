"""Controlli on-chain *di sola lettura* tramite RPC pubblici e API pubbliche.

- EVM (bsc, eth, polygon, arbitrum, base): getCode / nonce / saldo nativo / saldo USDT-USDC via JSON-RPC.
- BTC e LTC: statistiche indirizzo da API tipo mempool.space.
- TRON: saldo e flussi USDT (TRC20) da TronGrid.
- Sanzioni: indirizzi crypto della lista OFAC SDN (scaricata e messa in cache) + blocklist dell'utente.
- Tracciamento in avanti dei fondi (opzionale): richiede una API key compatibile Etherscan v2.

Gli indirizzi dei token (USDT/USDC) sono configurabili in EVM_CHAINS: verificali prima di usarli in un caso reale.
"""
from __future__ import annotations

import os
import re
import time
from typing import Optional

from .util import fmt_num, Finding, short

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

EVM_CHAINS = {
    "bsc": {"id": 56, "native": "BNB",
            "rpc": ["https://bsc-dataseed.binance.org", "https://bsc-rpc.publicnode.com"],
            "usdt": ("0x55d398326f99059fF775485246999027B3197955", 18),
            "usdc": ("0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", 18)},
    "eth": {"id": 1, "native": "ETH",
            "rpc": ["https://ethereum-rpc.publicnode.com"],
            "usdt": ("0xdAC17F958D2ee523a2206206994597C13D831ec7", 6),
            "usdc": ("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 6)},
    "polygon": {"id": 137, "native": "POL",
                "rpc": ["https://polygon-bor-rpc.publicnode.com"],
                "usdt": ("0xc2132D05D31c914a87C6611C10748AEb04B58e8F", 6),
                "usdc": ("0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", 6)},
    "arbitrum": {"id": 42161, "native": "ETH",
                 "rpc": ["https://arbitrum-one-rpc.publicnode.com"],
                 "usdt": ("0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", 6),
                 "usdc": ("0xaf88d065e77c8cC2239327C5EDb3A432268e5831", 6)},
    "base": {"id": 8453, "native": "ETH",
             "rpc": ["https://base-rpc.publicnode.com"],
             "usdc": ("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", 6)},
    "optimism": {"id": 10, "native": "ETH",
                 "rpc": ["https://optimism-rpc.publicnode.com"],
                 "usdt": ("0x94b008aA00579c1307B0EF2c499aD98a8ce58e58", 6),
                 "usdc": ("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", 6)},
    "avalanche": {"id": 43114, "native": "AVAX",
                  "rpc": ["https://avalanche-c-chain-rpc.publicnode.com"],
                  "usdt": ("0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7", 6),
                  "usdc": ("0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E", 6)},
}
TRON_USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
BTC_API = "https://mempool.space"
LTC_API = "https://litecoinspace.org"
TRONGRID = "https://api.trongrid.io"
SOLANA_RPC = ["https://api.mainnet-beta.solana.com", "https://solana-rpc.publicnode.com"]
SOL_USDT = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
SOL_USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
DOGE_API = "https://api.blockcypher.com/v1/doge/main/addrs"
ETHERSCAN_V2 = "https://api.etherscan.io/v2/api"

OFAC_URLS = [
    "https://www.treasury.gov/ofac/downloads/sdn.csv",
    "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.CSV",
]


# --------------------------------------------------------------------------- EVM
def _rpc(http, urls: list[str], method: str, params: list):
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    for u in urls:
        r = http.post_json(u, payload)
        if r and "result" in r and r["result"] is not None:
            return r["result"]
    return None


def _hex_int(x) -> Optional[int]:
    try:
        return int(x, 16)
    except (TypeError, ValueError):
        return None


def evm_snapshot(http, chain: str, addr: str) -> Optional[dict]:
    cfg = EVM_CHAINS[chain]
    urls = cfg["rpc"]
    code = _rpc(http, urls, "eth_getCode", [addr, "latest"])
    if code is None:
        return None
    nonce = _hex_int(_rpc(http, urls, "eth_getTransactionCount", [addr, "latest"])) or 0
    bal = _hex_int(_rpc(http, urls, "eth_getBalance", [addr, "latest"])) or 0
    block = _hex_int(_rpc(http, urls, "eth_blockNumber", []))
    tokens = {}
    for sym in ("usdt", "usdc"):
        if sym in cfg:
            contract, dec = cfg[sym]
            data = "0x70a08231" + addr[2:].lower().rjust(64, "0")
            res = _rpc(http, urls, "eth_call", [{"to": contract, "data": data}, "latest"])
            v = _hex_int(res)
            if v is not None:
                tokens[sym.upper()] = v / 10 ** dec
    return {"chain": chain, "type": "contract" if code not in ("0x", "0x0") else "EOA",
            "nonce": nonce, "native": bal / 1e18, "native_symbol": cfg["native"],
            "tokens": tokens, "block": block}


def evm_scan(http, addr: str, hints: Optional[list[str]] = None) -> list[dict]:
    """Interroga le chain EVM (quelle suggerite dal contesto, altrimenti tutte) e tiene quelle con attività."""
    chains = [h for h in (hints or []) if h in EVM_CHAINS] or list(EVM_CHAINS)
    out = []
    for ch in chains:
        s = evm_snapshot(http, ch, addr)
        if s and (s["nonce"] > 0 or s["native"] > 0 or any(v > 0 for v in s["tokens"].values())
                  or s["type"] == "contract"):
            out.append(s)
    return out


def decode_transfer_tx(http, chain: str, txhash: str) -> Optional[dict]:
    """Decodifica il primo evento ERC-20 Transfer della ricevuta (la tx fornita dalla vittima)."""
    cfg = EVM_CHAINS[chain]
    urls = cfg["rpc"]
    rec = _rpc(http, urls, "eth_getTransactionReceipt", [txhash])
    if not rec:
        return None
    for lg in rec.get("logs", []):
        t = lg.get("topics", [])
        if len(t) >= 3 and t[0].lower() == TRANSFER_TOPIC:
            contract = lg["address"]
            dec, sym = 18, "TOKEN"
            for s in ("usdt", "usdc"):
                if s in cfg and cfg[s][0].lower() == contract.lower():
                    dec, sym = cfg[s][1], s.upper()
            blk = _rpc(http, urls, "eth_getBlockByNumber", [rec["blockNumber"], False])
            ts = _hex_int(blk.get("timestamp")) if blk else None
            return {"chain": chain, "tx": txhash, "from": "0x" + t[1][-40:], "to": "0x" + t[2][-40:],
                    "token": sym, "contract": contract, "amount": (_hex_int(lg.get("data")) or 0) / 10 ** dec,
                    "block": _hex_int(rec.get("blockNumber")), "timestamp": ts,
                    "status": "ok" if _hex_int(rec.get("status")) == 1 else "failed"}
    return None


def explorer_tokentx(http, chain: str, addr: str, contract: str, key: str) -> list[dict]:
    cid = EVM_CHAINS[chain]["id"]
    url = (f"{ETHERSCAN_V2}?chainid={cid}&module=account&action=tokentx&address={addr}"
           f"&contractaddress={contract}&page=1&offset=200&sort=asc&apikey={key}")
    d = http.get_json(url)
    if not d or str(d.get("status")) != "1" or not isinstance(d.get("result"), list):
        return []
    return d["result"]


def trace_forward(http, chain: str, start: str, token_sym: str, key: str, first_amount: float,
                  since_ts: int = 0, max_hops: int = 4) -> list[dict]:
    """Segue in avanti l'importo da `start`: a ogni passo prende l'uscita ~uguale all'importo."""
    cfg = EVM_CHAINS[chain]
    contract, _ = cfg[token_sym.lower()]
    hops, cur, amount, ts0 = [], start, first_amount, since_ts
    for _ in range(max_hops):
        txs = explorer_tokentx(http, chain, cur, contract, key)
        outs = []
        for t in txs:
            if t.get("from", "").lower() != cur.lower() or int(t.get("timeStamp", 0)) < ts0:
                continue
            val = int(t["value"]) / 10 ** int(t.get("tokenDecimal", 18))
            outs.append((t, val))
        match = [(t, v) for t, v in outs if amount and abs(v - amount) <= 0.01 * amount]
        pick = match[0] if match else (max(outs, key=lambda x: x[1]) if outs else None)
        if not pick:
            break
        t, val = pick
        ts = int(t["timeStamp"])
        hops.append({"from": cur, "to": t["to"], "amount": val, "token": token_sym.upper(),
                     "tx": t["hash"], "timestamp": ts, "delay_s": (ts - ts0) if ts0 else None,
                     "matched_amount": bool(match)})
        cur, amount, ts0 = t["to"], val, ts
        snap = evm_snapshot(http, chain, cur)
        if snap and snap["type"] == "contract":
            hops[-1]["to_type"] = "contract"
            break
        hops[-1]["to_type"] = "EOA"
        hops[-1]["to_nonce"] = snap["nonce"] if snap else None
    return hops


# --------------------------------------------------------------------------- BTC / LTC / TRON
def utxo_snapshot(http, family: str, addr: str) -> Optional[dict]:
    base = BTC_API if family == "btc" else LTC_API
    d = http.get_json(f"{base}/api/address/{addr}")
    if not d:
        return None
    cs, ms = d.get("chain_stats", {}), d.get("mempool_stats", {})
    recv = cs.get("funded_txo_sum", 0) + ms.get("funded_txo_sum", 0)
    spent = cs.get("spent_txo_sum", 0) + ms.get("spent_txo_sum", 0)
    return {"chain": family, "type": "address", "native_symbol": family.upper(),
            "tx_count": cs.get("tx_count", 0) + ms.get("tx_count", 0),
            "received": recv / 1e8, "balance": (recv - spent) / 1e8}


def tron_snapshot(http, addr: str) -> Optional[dict]:
    acc = http.get_json(f"{TRONGRID}/v1/accounts/{addr}")
    data = (acc or {}).get("data") or []
    if acc is None:
        return None
    a = data[0] if data else {}
    usdt = 0.0
    for t in a.get("trc20", []) or []:
        if TRON_USDT in t:
            usdt = int(t[TRON_USDT]) / 1e6
    tx = http.get_json(f"{TRONGRID}/v1/accounts/{addr}/transactions/trc20?limit=200"
                       f"&only_confirmed=true&contract_address={TRON_USDT}")
    inflow = outflow = 0.0
    n = 0
    for r in (tx or {}).get("data", []):
        v = int(r.get("value", 0)) / 10 ** int((r.get("token_info") or {}).get("decimals", 6))
        n += 1
        if r.get("to") == addr:
            inflow += v
        elif r.get("from") == addr:
            outflow += v
    return {"chain": "tron", "type": "account" if data else "not-activated", "native_symbol": "TRX",
            "native": (a.get("balance", 0) or 0) / 1e6, "tokens": {"USDT": usdt},
            "tx_sampled": n, "usdt_in": inflow, "usdt_out": outflow,
            "created": a.get("create_time")}


def solana_snapshot(http, addr: str) -> Optional[dict]:
    """Saldo SOL, stato dell'account (esistente / programma eseguibile), token USDT/USDC e conteggio firme."""
    info = _rpc_obj(http, SOLANA_RPC, "getAccountInfo", [addr, {"encoding": "base64"}])
    if info is None:
        return None
    val = info.get("value")
    sigs = _rpc_obj(http, SOLANA_RPC, "getSignaturesForAddress", [addr, {"limit": 1000}])
    tokens = {}
    for sym, mint in (("USDT", SOL_USDT), ("USDC", SOL_USDC)):
        r = _rpc_obj(http, SOLANA_RPC, "getTokenAccountsByOwner",
                     [addr, {"mint": mint}, {"encoding": "jsonParsed"}])
        tot = 0.0
        for acc in (r or {}).get("value", []):
            try:
                tot += float(acc["account"]["data"]["parsed"]["info"]["tokenAmount"]["uiAmount"] or 0)
            except (KeyError, TypeError, ValueError):
                pass
        tokens[sym] = tot
    exists = val is not None
    return {"chain": "sol", "type": ("program" if exists and val.get("executable") else
                                      "account" if exists else "not-activated"),
            "native_symbol": "SOL", "native": ((val or {}).get("lamports", 0) or 0) / 1e9,
            "tokens": tokens, "tx_sampled": len(sigs or []), "sig_cap_hit": len(sigs or []) >= 1000}


def _rpc_obj(http, urls: list[str], method: str, params: list):
    """Come _rpc ma accetta anche risultati vuoti/zero (Solana ritorna {'value': None} per account inesistenti)."""
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    for u in urls:
        r = http.post_json(u, payload)
        if r and "result" in r and r["result"] is not None:
            return r["result"]
    return None


def doge_snapshot(http, addr: str) -> Optional[dict]:
    d = http.get_json(f"{DOGE_API}/{addr}/balance")
    if not isinstance(d, dict) or "final_balance" not in d:
        return None
    recv = d.get("total_received", 0) / 1e8
    return {"chain": "doge", "type": "address", "native_symbol": "DOGE",
            "tx_count": d.get("final_n_tx", d.get("n_tx", 0)), "received": recv,
            "balance": d.get("final_balance", 0) / 1e8}


# --------------------------------------------------------------------------- blocklist / sanzioni
class Blocklists:
    """Insiemi di indirizzi noti come sanzionati o segnalati (lowercase)."""

    def __init__(self) -> None:
        self.sets: dict[str, set[str]] = {}

    def load_ofac(self, http, cache_dir: str = ".osintr_cache", max_age_h: int = 24) -> bool:
        os.makedirs(cache_dir, exist_ok=True)
        path = os.path.join(cache_dir, "ofac_sdn.csv")
        text = None
        if os.path.exists(path) and time.time() - os.path.getmtime(path) < max_age_h * 3600:
            text = open(path, encoding="utf-8", errors="replace").read()
        else:
            for u in OFAC_URLS:
                r = http.get(u)
                if r.ok and len(r.body) > 10_000:
                    text = r.text
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(text)
                    break
        if not text:
            return False
        addrs = {m.group(2).lower() for m in
                 re.finditer(r"Digital Currency Address - ([A-Z0-9]{2,10}) ([A-Za-z0-9]{20,})", text)}
        self.sets["OFAC SDN"] = addrs
        return True

    def load_file(self, path: str, name: Optional[str] = None) -> None:
        with open(path, encoding="utf-8") as f:
            vals = {ln.strip().split()[0].lower() for ln in f if ln.strip() and not ln.startswith("#")}
        self.sets[name or os.path.basename(path)] = vals

    def match(self, addr: str) -> list[str]:
        a = addr.lower()
        return [n for n, s in self.sets.items() if a in s]


# --------------------------------------------------------------------------- interpretazione
def _fmt_tokens(tokens: dict, lang: str = "it") -> str:
    return ", ".join(f"{fmt_num(v, 2, lang)} {k}" for k, v in tokens.items() if v) or "0"


def interpret_snapshot(addr: str, snap: dict, basis: str, lang: str = "it") -> list[Finding]:
    out: list[Finding] = []
    chain = snap["chain"]
    if chain in EVM_CHAINS and snap["type"] == "EOA":
        n = snap["nonce"]
        if n >= 1000:
            sev, conf = "high", "medium"
        elif n >= 100:
            sev, conf = "medium", "low"
        else:
            return out
        out.append(Finding("ONC_COLLECTOR", sev, conf, "interpretation", "onchain", basis,
                           {"addr": short(addr), "chain": chain, "nonce": n,
                            "balance": _fmt_tokens(snap["tokens"], lang)}))
    elif chain in ("btc", "ltc", "doge"):
        if snap["tx_count"] >= 50 and snap["received"] > 0 and snap["balance"] < 0.05 * snap["received"]:
            out.append(Finding("ONC_STATS_PASSTHROUGH", "medium", "low", "interpretation", "onchain", basis,
                               {"addr": short(addr), "chain": chain,
                                "received": f"{snap['received']:.4f} {chain.upper()}",
                                "balance": f"{snap['balance']:.4f} {chain.upper()}"}))
    elif chain == "sol":
        if snap["type"] == "account" and snap.get("tx_sampled", 0) >= 500:
            out.append(Finding("ONC_COLLECTOR", "medium", "low", "interpretation", "onchain", basis,
                               {"addr": short(addr), "chain": "sol", "nonce": f"{snap['tx_sampled']}+ firme",
                                "balance": _fmt_tokens(snap["tokens"], lang)}))
    elif chain == "tron":
        if snap.get("usdt_in", 0) > 0 and snap["tx_sampled"] >= 50 and \
                snap["usdt_out"] >= 0.95 * snap["usdt_in"]:
            out.append(Finding("ONC_STATS_PASSTHROUGH", "medium", "low", "interpretation", "onchain", basis,
                               {"addr": short(addr), "chain": "tron",
                                "received": f"{fmt_num(snap['usdt_in'], 2, lang)} USDT",
                                "balance": f"{fmt_num(snap['tokens'].get('USDT', 0), 2, lang)} USDT"}))
    return out


def list_findings(addr: str, lists: list[str], basis: str) -> list[Finding]:
    if not lists:
        return []
    sanct = [x for x in lists if "OFAC" in x]
    out = []
    if sanct:
        out.append(Finding("ONC_SANCTIONED", "critical", "high", "fact", "onchain", basis,
                           {"addr": short(addr), "lists": ", ".join(sanct)}))
    other = [x for x in lists if "OFAC" not in x]
    if other:
        out.append(Finding("ONC_BLOCKLIST", "high", "medium-high", "fact", "onchain", basis,
                           {"addr": short(addr), "lists": ", ".join(other)}))
    return out
