import pytest

from osintr_ext import demo, discover, webscan
from osintr_ext.fakehttp import FakeHttp

SITE = "https://shop.example"


@pytest.mark.parametrize("code,expected", [
    ("fetch('/api/z')", ["/api/z"]),
    ("$.get('/api/finance', cb)", ["/api/finance"]),
    ("axios.get('/api/q')", ["/api/q"]),
    ("$.ajax({url:'/api/b', type:'GET'})", ["/api/b"]),
    ("xhr.open('GET','/api/d')", ["/api/d"]),
    ("const C = {endpoint: '/api/finance'}", ["/api/finance"]),
    # scritture: mai richieste
    ("$.post('/api/x', {})", []),
    ("axios.post('/api/y', {})", []),
    ("fetch('/api/w', {method: 'POST'})", []),
    ("$.ajax({url:'/api/a', type:'POST'})", []),
    ("xhr.open('POST','/api/c')", []),
    # un POST vicino non deve far scartare un GET separato
    ("$.ajax({type:'POST', url:'data.php', data:{a:1}});\nfoo();\n$.get('/api/finance')", ["/api/finance"]),
])
def test_candidates_and_write_detection(code, expected):
    got = [c for c in discover.endpoint_candidates(code) if c.startswith("/api") or c == "data.php"]
    assert got == expected


def test_header_names_and_template_literals_are_not_endpoints():
    # regressione: Map/Headers/URLSearchParams .get(...) veniva scambiato per una richiesta di rete
    garbage = [
        "headers.get('X-Vinext-Rsc-Completion-Metadata')",
        "params.get(`${t.id}::${r}`)",
        "res.headers.get('content-type')",
        "headers.get('X-Vinext-Params')",
    ]
    for code in garbage:
        assert discover.endpoint_candidates(code) == [], code


def test_get_on_an_http_client_is_still_found():
    for code, expected in (
        ("apiClient.get('/api/accounts')", "/api/accounts"),
        ("httpService.get('/api/returns')", "/api/returns"),
        ("restClient.get('/api/wallet')", "/api/wallet"),
    ):
        assert discover.endpoint_candidates(code) == [expected], code


def test_acceptable_rules():
    seen: set = set()
    ok = lambda u: discover._acceptable(u, "shop.example", seen)
    assert ok(SITE + "/api/finance")
    assert not ok("https://evil.example/api/finance")            # altro host
    assert not ok(SITE + "/api/logout") and not ok(SITE + "/api/withdraw")
    assert not ok(SITE + "/assets/app.js") and not ok(SITE + "/logo.png")
    assert not ok(SITE + "/")
    assert not ok("ftp://shop.example/api/x")
    assert ok("https://www.shop.example/api/finance")             # www equivale all'host


def test_scan_site_reads_hidden_endpoint_and_never_writes():
    http = demo.build_fake_http()
    r = webscan.scan_site(http, demo.SITE)
    srcs = {a["address"].lower(): a.get("source") for a in r["addresses"]}
    assert srcs[demo.WD.lower()] == "endpoint:/api/finance"           # non e' nella pagina
    assert not any(c.startswith("POST ") and "rpc" not in c for c in http.calls)
    assert not any("logout" in c or "data.php" in c for c in http.calls)
    assert all(c.startswith(("GET ", "POST ")) for c in http.calls)


def test_discover_can_be_disabled():
    http = demo.build_fake_http()
    r = webscan.scan_site(http, demo.SITE, discover_enabled=False)
    assert r["endpoints"] == [] and demo.WD.lower() not in {a["address"].lower() for a in r["addresses"]}


def test_caps_errors_and_non_text_responses():
    http = FakeHttp()
    js = "".join(f"fetch('/api/e{i}');" for i in range(100)) + "fetch('/api/secret');fetch('/api/img');"
    http.add(SITE, '<html><body><script src="/a.js"></script></body></html>')
    http.add(SITE + "/a.js", js)
    http.add(SITE + "/api/secret", {"error": "unauthorized"}, status=401)
    http.add(SITE + "/api/img", b"\x89PNG\r\n" + b"0" * 100, headers={"content-type": "image/png"})
    r = webscan.scan_site(http, SITE)
    assert len(r["endpoints"]) <= discover.MAX_ENDPOINTS and r["endpoints_skipped"] >= 20
    # una risposta 401 viene registrata ma non interpretata
    http2 = FakeHttp()
    http2.add(SITE, '<html><body><script src="/a.js"></script></body></html>')
    http2.add(SITE + "/a.js", "fetch('/api/secret');fetch('/api/img');")
    http2.add(SITE + "/api/secret", {"error": "unauthorized"}, status=401)
    http2.add(SITE + "/api/img", b"\x89PNG\r\n" + b"0" * 100, headers={"content-type": "image/png"})
    r2 = webscan.scan_site(http2, SITE)
    by = {e["url"].rsplit("/", 1)[-1]: e for e in r2["endpoints"]}
    assert by["secret"]["status"] == 401 and by["secret"]["addresses"] == []
    assert by["img"]["addresses"] == []


def test_auth_required_is_logged_and_not_read_further():
    http = FakeHttp()
    http.add(SITE, '<html><body><script src="/a.js"></script></body></html>')
    http.add(SITE + "/a.js", "fetch('/api/wallet');")
    http.add(SITE + "/api/wallet", "Sign in to continue", status=401)
    r = webscan.scan_site(http, SITE)
    e = r["endpoints"][0]
    assert e["status"] == 401 and e["auth_required"] is True
    assert e["addresses"] == [] and "sha256" not in e


def test_response_field_categorization():
    body = b'{"wallet_balance": 120.5, "transactions": [], "arbitrage": {"pair": "BTC/USDT"}}'
    cat = discover.categorize_response(body)
    assert set(cat["categories"]) >= {"wallet_saldo", "transazioni", "arbitraggio_trading"}
    assert discover.categorize_response(b"<html>not json, no keywords here</html>") == {
        "fields": [], "categories": [], "auth_required": False}


def test_internal_pages_with_payment_hints_are_read():
    http = FakeHttp()
    wallet = demo.WD
    http.add(SITE, '<html><body><a href="/deposit">Deposit</a><a href="/blog">blog</a>'
                         '<a href="/logout">out</a><a href="https://other.example/wallet">x</a></body></html>')
    http.add(SITE + "/deposit", f"<html><body>Send USDT to {wallet}</body></html>")
    r = webscan.scan_site(http, SITE)
    assert [p["url"] for p in r["pages"]] == [SITE + "/deposit"]
    assert wallet.lower() in {a["address"].lower() for a in r["addresses"]}
    assert not any("blog" in c or "logout" in c or "other.example" in c for c in http.calls)


def test_header_names_and_template_literals_are_not_treated_as_endpoints():
    # regressione: un framework interno (es. Next.js) che usa "url:" o ".get(...)" per nomi di header o chiavi di
    # cache veniva scambiato per un endpoint da richiedere
    code = """
    doFetch({method:'GET', url:'X-Vinext-Params'});
    cache.get(`${t.id}::${r}`);
    headers.get('content-type');
    apiClient.get('/api/real-endpoint');
    """
    got = discover.endpoint_candidates(code)
    assert got == ["/api/real-endpoint"]


@pytest.mark.parametrize("bad", ["content-type", "Content-Type", "X-Vinext-Params", "${t.id}::${r}",
                                 "X-Vinext-Stale-Time-Pending", "has space", "a\\nb"])
def test_looks_like_path_rejects_non_paths(bad):
    assert discover._looks_like_path(bad) is False


@pytest.mark.parametrize("ok", ["/api/finance", "/api/wallet?x=1", "https://x.example/a", "data.php",
                                "report.json?id=1", "//cdn.example/x"])
def test_looks_like_path_accepts_real_paths(ok):
    assert discover._looks_like_path(ok) is True


def test_progress_callback_reports_periodically_during_endpoint_scan():
    http = FakeHttp()
    js = "".join(f"fetch('/api/e{i}');" for i in range(14))
    http.add(SITE, '<html><body><script src="/a.js"></script></body></html>')
    http.add(SITE + "/a.js", js)
    for i in range(14):
        http.add(f"{SITE}/api/e{i}", {"ok": True})
    seen = []
    webscan.scan_site(http, SITE, progress=lambda m: seen.append(m))
    endpoint_msgs = [m for m in seen if "endpoint" in m]
    assert len(endpoint_msgs) >= 3          # non un solo messaggio per 14 richieste
    assert "1/14" in endpoint_msgs[0]


def test_progress_callback_is_optional():
    http = demo.build_fake_http()
    webscan.scan_site(http, demo.SITE)      # nessun progress passato: non deve sollevare eccezioni
