"""Estrazione e validazione degli indirizzi crypto presenti in HTML/JS.

Famiglie supportate: evm (0x...), btc (legacy + bech32), ltc (legacy + bech32), tron (T...).
Gli indirizzi base58/bech32 sono accettati solo se il checksum è valido, così i falsi positivi
(hash, token, stringhe casuali nel JS) sono praticamente azzerati. Solana/XRP/Monero non sono
coperti (nessun checksum semplice o formato ambiguo): sono un limite noto.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


# --------------------------------------------------------------------------- codifiche
def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        i = B58.find(c)
        if i < 0:
            raise ValueError("carattere base58 non valido")
        n = n * 58 + i
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


def b58check_payload(s: str) -> bytes:
    raw = b58decode(s)
    if len(raw) < 5:
        raise ValueError("troppo corto")
    payload, chk = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != chk:
        raise ValueError("checksum errato")
    return payload


def b58encode_check(payload: bytes) -> str:
    """Usato nei test per generare indirizzi sintetici validi."""
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + out


def _polymod(values) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def bech32_verify(addr: str) -> tuple[bool, str]:
    """Ritorna (valido, hrp). Accetta sia bech32 sia bech32m."""
    if addr.lower() != addr and addr.upper() != addr:
        return False, ""
    a = addr.lower()
    pos = a.rfind("1")
    if pos < 1 or pos + 7 > len(a) or len(a) > 90:
        return False, ""
    hrp = a[:pos]
    data = []
    for c in a[pos + 1:]:
        i = BECH32_CHARSET.find(c)
        if i < 0:
            return False, ""
        data.append(i)
    expand = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    return _polymod(expand + data) in (1, 0x2BC830A3), hrp


# --------------------------------------------------------------------------- regex
EVM_RE = re.compile(r"(?<![0-9A-Za-z])0x[0-9a-fA-F]{40}(?![0-9A-Za-z])")
BTC_LEGACY_RE = re.compile(r"(?<![0-9A-Za-z])[13][1-9A-HJ-NP-Za-km-z]{25,34}(?![0-9A-Za-z])")
LTC_LEGACY_RE = re.compile(r"(?<![0-9A-Za-z])[LM][1-9A-HJ-NP-Za-km-z]{26,33}(?![0-9A-Za-z])")
TRON_RE = re.compile(r"(?<![0-9A-Za-z])T[1-9A-HJ-NP-Za-km-z]{33}(?![0-9A-Za-z])")
DOGE_RE = re.compile(r"(?<![0-9A-Za-z])D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}(?![0-9A-Za-z])")
SOL_RE = re.compile(r"(?<![0-9A-Za-z])[1-9A-HJ-NP-Za-km-z]{32,44}(?![0-9A-Za-z])")
SOL_CTX = ("solana", "sol ", " sol", "spl", "phantom", "solflare", "$sol", "sol:", "(sol)")
BECH32_RE = re.compile(r"(?<![0-9A-Za-z])(?:bc1|ltc1)[0-9a-z]{11,87}(?![0-9A-Za-z])", re.I)

HINTS = {
    "bsc": ("bep20", "bep-20", "bsc", "bnb smart", "binance smart", "bnb chain"),
    "eth": ("erc20", "erc-20", "ethereum"),
    "tron": ("trc20", "trc-20", "tron"),
    "polygon": ("polygon", "matic"),
    "arbitrum": ("arbitrum",),
    "optimism": ("optimism", "op mainnet"),
    "avalanche": ("avalanche", "avax", "c-chain"),
    "base": ("base network", "on base"),
    "btc": ("bitcoin", "btc"),
    "sol": ("solana", "spl"),
    "doge": ("dogecoin", "doge"),
}


@dataclass
class FoundAddress:
    address: str
    family: str                      # evm|btc|ltc|tron|sol|doge
    source: str = ""
    context: str = ""
    hints: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _is_placeholder(addr: str) -> bool:
    body = addr[2:].lower()
    return len(set(body)) <= 3


def _context(text: str, start: int, end: int, width: int = 90) -> str:
    seg = text[max(0, start - width): min(len(text), end + width)]
    return re.sub(r"\s+", " ", seg).strip()


def _hints(ctx: str) -> list[str]:
    low = ctx.lower()
    return [net for net, keys in HINTS.items() if any(k in low for k in keys)]


def find_addresses(text: str, source: str = "") -> list[FoundAddress]:
    """Trova indirizzi validi in `text`. Deduplica per (famiglia, indirizzo)."""
    found: dict[tuple[str, str], FoundAddress] = {}

    def add(addr: str, family: str, m: re.Match) -> None:
        key = (family, addr.lower() if family in ("evm", "btc", "ltc") else addr)
        if key not in found:
            ctx = _context(text, m.start(), m.end())
            found[key] = FoundAddress(addr, family, source, ctx, _hints(ctx))

    for m in EVM_RE.finditer(text):
        if not _is_placeholder(m.group()):
            add(m.group(), "evm", m)
    for m in BTC_LEGACY_RE.finditer(text):
        try:
            p = b58check_payload(m.group())
        except ValueError:
            continue
        if len(p) == 21 and p[0] in (0x00, 0x05):
            add(m.group(), "btc", m)
    for m in LTC_LEGACY_RE.finditer(text):
        try:
            p = b58check_payload(m.group())
        except ValueError:
            continue
        if len(p) == 21 and p[0] in (0x30, 0x32, 0x05):
            add(m.group(), "ltc", m)
    for m in TRON_RE.finditer(text):
        try:
            p = b58check_payload(m.group())
        except ValueError:
            continue
        if len(p) == 21 and p[0] == 0x41:
            add(m.group(), "tron", m)
    for m in BECH32_RE.finditer(text):
        ok, hrp = bech32_verify(m.group())
        if ok and hrp in ("bc", "ltc"):
            add(m.group(), "btc" if hrp == "bc" else "ltc", m)
    for m in DOGE_RE.finditer(text):
        try:
            p = b58check_payload(m.group())
        except ValueError:
            continue
        if len(p) == 21 and p[0] in (0x1E, 0x16):
            add(m.group(), "doge", m)
    for m in SOL_RE.finditer(text):
        tok = m.group()
        if tok in {a for (_, a) in found} or len(tok) < 32:
            continue
        try:
            raw = b58decode(tok)
        except ValueError:
            continue
        ctx = _context(text, m.start(), m.end()).lower()
        # un token base58 di 32 byte è ovunque (hash, id): lo accettiamo solo con contesto Solana esplicito
        if len(raw) == 32 and any(k in ctx for k in SOL_CTX) and len(set(tok)) > 12:
            add(tok, "sol", m)
    return list(found.values())


def classify(address: str) -> str:
    """Famiglia di un indirizzo dato dall'utente ('' se non riconosciuto)."""
    address = address.strip()
    hits = find_addresses(f" {address} ")
    if hits and hits[0].address.lower() == address.lower():
        return hits[0].family
    # indirizzo dato esplicitamente dall'utente: per Solana basta che sia base58 di 32 byte
    if 32 <= len(address) <= 44 and SOL_RE.fullmatch(address):
        try:
            if len(b58decode(address)) == 32 and len(set(address)) > 12:
                return "sol"
        except ValueError:
            pass
    return ""
