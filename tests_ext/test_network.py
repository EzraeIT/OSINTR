import subprocess

from osintr_ext import demo, network
from osintr_ext.bridge import case_from_scan


def _corr(kind, value, strength, targets):
    return {"type": kind, "value": value, "strength": strength, "targets": targets}


def _domain_entry(name="arbitrage-demo.example"):
    scan = demo.build_demo_scan()
    scan["target"] = name
    http = demo.build_fake_http()
    case = case_from_scan(scan, http, lang="it")
    return (name, "domain", scan, case)


def test_mixed_target_types_in_overview_table():
    entries = [
        _domain_entry("arbitrage-demo.example"),
        ("mario@esempio.com", "email", {"type": "email"}, None),
        ("11.222.333/0001-81", "cnpj", {"type": "cnpj"}, None),
    ]
    corr = [_corr("Wallet btc", "bc1qxyz", "strong", ["arbitrage-demo.example", "mario@esempio.com"])]
    net = network.build_network_case(entries, corr, analyst="Test")
    types = {t["target"]: t["type"] for t in net["targets"]}
    assert types == {"arbitrage-demo.example": "domain", "mario@esempio.com": "email",
                     "11.222.333/0001-81": "cnpj"}
    # i target senza caso forense (non domini) non hanno un livello di rischio
    non_domain = [t for t in net["targets"] if t["type"] != "domain"]
    assert all(t["level"] is None for t in non_domain)
    domain_row = next(t for t in net["targets"] if t["type"] == "domain")
    assert domain_row["level"] == "critical"


def test_btc_wallet_correlation_is_carried_through():
    entries = [_domain_entry("a.example"), _domain_entry("b.example")]
    corr = [_corr("Wallet btc", "bc1qsharedaddress", "strong", ["a.example", "b.example"])]
    net = network.build_network_case(entries, corr)
    assert net["shared"] == [{"kind": "Wallet btc", "value": "bc1qsharedaddress", "strength": "strong",
                              "targets": ["a.example", "b.example"]}]


def test_weak_vs_strong_correlation_labels_preserved():
    entries = [_domain_entry("a.example"), _domain_entry("b.example")]
    corr = [_corr("CNPJ", "11222333000181", "strong", ["a.example", "b.example"]),
            _corr("IP", "203.0.113.1", "weak", ["a.example", "b.example"])]
    net = network.build_network_case(entries, corr)
    strengths = {s["kind"]: s["strength"] for s in net["shared"]}
    assert strengths == {"CNPJ": "strong", "IP": "weak"}


def test_no_correlations_means_empty_shared_list():
    entries = [_domain_entry("a.example"), _domain_entry("b.example")]
    net = network.build_network_case(entries, [])
    assert net["shared"] == []


def test_report_renders_mixed_types_and_strength_column(tmp_path):
    entries = [
        _domain_entry("arbitrage-demo.example"),
        ("mario@esempio.com", "email", {"type": "email"}, None),
    ]
    corr = [_corr("Wallet btc", "bc1qxyz", "strong", ["arbitrage-demo.example", "mario@esempio.com"]),
            _corr("IP", "203.0.113.1", "weak", ["arbitrage-demo.example", "mario@esempio.com"])]
    net = network.build_network_case(entries, corr, analyst="Test", lang="it")
    pdf = str(tmp_path / "net.pdf")
    network.render_network_report(net, pdf, lang="it")
    txt = subprocess.run(["pdftotext", "-layout", pdf, "-"], capture_output=True, text=True).stdout
    assert "mario@esempio.com" in txt and "non applicabile" in txt
    assert "forte" in txt and "da verificare" in txt
    assert "Wallet btc" in txt


def test_report_english_labels(tmp_path):
    entries = [_domain_entry("a.example"), ("mario@esempio.com", "email", {}, None)]
    corr = [_corr("CNPJ", "11222333000181", "strong", ["a.example", "mario@esempio.com"])]
    net = network.build_network_case(entries, corr, lang="en")
    pdf = str(tmp_path / "net_en.pdf")
    network.render_network_report(net, pdf, lang="en")
    txt = subprocess.run(["pdftotext", "-layout", pdf, "-"], capture_output=True, text=True).stdout
    assert "strong" in txt and "not applicable" in txt


def test_report_with_no_shared_identifiers_says_so(tmp_path):
    entries = [_domain_entry("a.example"), _domain_entry("b.example")]
    net = network.build_network_case(entries, [])
    pdf = str(tmp_path / "none.pdf")
    network.render_network_report(net, pdf, lang="it")
    txt = subprocess.run(["pdftotext", "-layout", pdf, "-"], capture_output=True, text=True).stdout
    assert "Nessun identificativo condiviso" in txt
