"""Client HTTP finto, per test e demo offline: serve risposte da un dizionario o da gestori registrati."""
from __future__ import annotations

import json
from typing import Callable, Optional

from .util import Response


class FakeHttp:
    def __init__(self) -> None:
        self.routes: list[tuple[str, Callable[[str], Optional[Response]]]] = []
        self.rpc_handlers: dict[str, Callable[[str, list], object]] = {}
        self.calls: list[str] = []

    # --- registrazione
    def add(self, prefix: str, body, status: int = 200, headers: Optional[dict] = None,
            cookies: Optional[list] = None, exact: bool = True) -> None:
        raw = body if isinstance(body, bytes) else (body.encode() if isinstance(body, str) else json.dumps(body).encode())
        resp = Response(prefix, status, {k.lower(): v for k, v in (headers or {}).items()}, raw, cookies or [])
        fn = lambda url, r=resp: Response(url, r.status, r.headers, r.body, r.set_cookies)
        self.routes.append((prefix if not exact else "=" + prefix, fn))

    def add_rpc(self, url_prefix: str, handler: Callable[[str, list], object]) -> None:
        self.rpc_handlers[url_prefix] = handler

    # --- interfaccia Http
    def get(self, url: str, headers: Optional[dict] = None) -> Response:
        self.calls.append("GET " + url)
        for prefix, fn in sorted(self.routes, key=lambda x: -len(x[0])):
            if (prefix[1:] == url) if prefix.startswith("=") else url.startswith(prefix):
                return fn(url)
        return Response(url, 404, {}, b"", [], error="404 (fake)")

    def request(self, url: str, method: str = "GET", headers=None, data=None) -> Response:
        return self.get(url, headers)

    def get_json(self, url: str, headers: Optional[dict] = None):
        r = self.get(url, headers)
        if not r.ok:
            return None
        try:
            return r.json()
        except ValueError:
            return None

    def post_json(self, url: str, payload: dict, headers: Optional[dict] = None):
        self.calls.append(f"POST {url} {payload.get('method')}")
        for prefix, h in self.rpc_handlers.items():
            if url.startswith(prefix):
                res = h(payload["method"], payload.get("params", []))
                return {"jsonrpc": "2.0", "id": 1, "result": res}
        return None
