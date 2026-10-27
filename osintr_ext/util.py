"""Utility condivise: HTTP passivo, hashing, redazione, modello Finding e valutazione del rischio."""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Optional

VERSION = "0.1.0"


def user_agent() -> str:
    contact = os.environ.get("OSINTR_CONTACT", "")
    extra = f"; {contact}" if contact else ""
    return f"osintr-ext/{VERSION} (passive OSINT{extra})"


# --------------------------------------------------------------------------- HTTP
@dataclass
class Response:
    url: str
    status: int
    headers: dict
    body: bytes
    set_cookies: list = field(default_factory=list)
    error: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def json(self):
        return json.loads(self.body.decode("utf-8", "replace"))


class Http:
    """Client HTTP minimale e *passivo*: solo GET/POST verso API pubbliche e pagine pubbliche.

    Throttling per host, timeout, limite di dimensione. Nessuna autenticazione sui siti analizzati.
    """

    def __init__(self, timeout: int = 15, max_bytes: int = 3_000_000, delay: float = 0.4, retries: int = 1):
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.delay = delay
        self.retries = retries
        self._last: dict[str, float] = {}

    def _throttle(self, host: str) -> None:
        wait = self.delay - (time.monotonic() - self._last.get(host, 0.0))
        if wait > 0:
            time.sleep(wait)
        self._last[host] = time.monotonic()

    def request(self, url: str, method: str = "GET", headers: Optional[dict] = None,
                data: Optional[bytes] = None) -> Response:
        self._throttle(urllib.parse.urlparse(url).netloc)
        h = {"User-Agent": user_agent(), "Accept": "*/*"}
        h.update(headers or {})
        req = urllib.request.Request(url, data=data, headers=h, method=method)
        attempt = 0
        while True:
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    body = r.read(self.max_bytes + 1)[: self.max_bytes]
                    return Response(r.geturl(), r.status, {k.lower(): v for k, v in r.headers.items()},
                                    body, r.headers.get_all("Set-Cookie") or [])
            except urllib.error.HTTPError as e:
                body = e.read(self.max_bytes) if e.fp else b""
                return Response(url, e.code, {k.lower(): v for k, v in e.headers.items()}, body,
                                e.headers.get_all("Set-Cookie") or [], error=str(e))
            except Exception as e:  # rete, TLS, timeout...
                attempt += 1
                if attempt > self.retries:
                    return Response(url, 0, {}, b"", [], error=f"{type(e).__name__}: {e}")
                time.sleep(1)

    def get(self, url: str, headers: Optional[dict] = None) -> Response:
        return self.request(url, "GET", headers)

    def get_json(self, url: str, headers: Optional[dict] = None):
        r = self.get(url, headers)
        if not r.ok:
            return None
        try:
            return r.json()
        except ValueError:
            return None

    def post_json(self, url: str, payload: dict, headers: Optional[dict] = None):
        h = {"Content-Type": "application/json"}
        h.update(headers or {})
        r = self.request(url, "POST", h, json.dumps(payload).encode())
        if not r.ok:
            return None
        try:
            return r.json()
        except ValueError:
            return None


# --------------------------------------------------------------------------- hashing / redazione
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest().upper()


def fmt_num(x: float, dec: int = 2, lang: str = "it") -> str:
    """1500.99 -> '1.500,99' (it) / '1,500.99' (en)."""
    out = f"{x:,.{dec}f}"
    return out.replace(",", "X").replace(".", ",").replace("X", ".") if lang == "it" else out


def short(s: str, head: int = 6, tail: int = 4) -> str:
    """Abbrevia un identificativo (indirizzo, tx hash) per le copie privacy-safe."""
    if not s or len(s) <= head + tail + 3:
        return s
    return f"{s[:head]}...{s[-tail:]}"


# --------------------------------------------------------------------------- findings
SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEV_W = {"critical": 5, "high": 3, "medium": 2, "low": 1, "info": 0}
CONF_W = {"high": 1.0, "medium-high": 0.8, "medium": 0.6, "low": 0.3}
KINDS = ("fact", "interpretation", "limit")


@dataclass
class Finding:
    code: str                      # chiave in findings_text.TEXT (oppure "MANUAL")
    severity: str                  # critical|high|medium|low|info
    confidence: str                # high|medium-high|medium|low
    kind: str                      # fact|interpretation|limit
    area: str                      # onchain|code|economics|entity|domain|web|manual
    basis: str = ""                # fonte dell'evidenza
    params: dict = field(default_factory=dict)
    title: str = ""                # solo per i finding manuali
    detail: str = ""               # solo per i finding manuali
    id: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Finding":
        return Finding(
            code=d["code"], severity=d["severity"], confidence=d["confidence"], kind=d["kind"],
            area=d.get("area", "manual"), basis=d.get("basis", ""), params=d.get("params", {}) or {},
            title=d.get("title", ""), detail=d.get("detail", ""), id=d.get("id", ""))


def assess(findings: list[Finding]) -> tuple[str, float]:
    """Livello complessivo (critical|high|medium|low) e punteggio.

    I finding di tipo 'limit' non contano. È una sintesi euristica: la decisione finale spetta all'analista.
    """
    scored = [f for f in findings if f.kind != "limit"]
    score = sum(SEV_W[f.severity] * CONF_W[f.confidence] for f in scored)
    strong_crit = sum(1 for f in scored if f.severity == "critical" and CONF_W[f.confidence] >= 0.8)
    if strong_crit >= 2 or score >= 12:
        level = "critical"
    elif strong_crit >= 1 or score >= 7:
        level = "high"
    elif score >= 3:
        level = "medium"
    else:
        level = "low"
    return level, round(score, 1)
