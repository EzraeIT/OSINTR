from osintr_ext import webscan as W


def test_rate_period_is_the_nearest_keyword():
    # regressione: "5% monthly. ... 1.2% daily" veniva letto come "5% daily"
    t = W.analyze_text("Earn up to 5% monthly. Sign up and get 1.2% daily on balance.")
    got = {(r["rate"], r["period"]) for r in t["rates"]}
    assert got == {(5.0, "monthly"), (1.2, "daily")}
    assert {r["annual"] for r in t["rates"]} == {60.0, 438.0}


def test_italian_and_spanish_periods():
    t = W.analyze_text("Rendimento del 3% al mese. Ganancia del 0,5% por día.")
    got = {(r["rate"], r["period"]) for r in t["rates"]}
    assert (3.0, "monthly") in got and (0.5, "daily") in got


def test_guarantee_pressure_referral():
    t = W.analyze_text("Guaranteed profits, risk-free. Limited spots! Referral bonus 7% for invites.")
    assert t["guarantees"] and t["pressure"] and t["referral"] == ["7%"]


def test_js_random_with_financial_keywords_and_upload():
    code = """
    var amount = Math.floor(Math.random()*100); var spread = Math.random()*0.002; var profit = amount*spread;
    $.ajax({type:'POST', url:'data.php', data:{amount:amount, profit:profit, spread:spread}});
    setInterval(function(){ $.get('get_last_deal.php', function(d){}); }, 30000);
    """
    r = W.analyze_js("x.js", code)
    assert r["random_hits"] and r["uploads"] and r["feed"]


def test_js_random_without_finance_is_ignored():
    r = W.analyze_js("ui.js", "var color = Math.random() > 0.5 ? 'red' : 'blue';")
    assert r["random_hits"] == []


def test_site_findings_legal_missing_and_old_php():
    scan = {"status": 200, "text": {}, "random_hits": [], "feed": [], "company_mentions": {"names": ["X Ltd"], "ids": []},
            "legal_pages": [], "legal_links_found": False, "server": "Apache", "x_powered_by": "PHP/7.2.34",
            "security_headers": {"CSP": False, "HSTS": False, "XFO": False}, "cors": {}, "cookie_issues": []}
    codes = {f.code for f in W.site_findings(scan)}
    assert {"WEB_LEGAL_MISSING", "WEB_OLD_SERVER", "WEB_HEADERS_MISSING"} <= codes
