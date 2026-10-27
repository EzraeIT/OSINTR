import datetime

import pytest

pytest.importorskip("reportlab", reason='pip install "reportlab<5"')

from osintr_ext import bridge, demo, report
from osintr_ext.case import all_findings


def codes(case):
    return {f.code for f in all_findings(case)}


@pytest.fixture(scope="module")
def case():
    return bridge.case_from_scan(
        demo.build_demo_scan(), demo.build_fake_http(), tx=demo.TX, tx_chain="bsc", etherscan_key="demo",
        meta={"analyst": "test", "redact": True},
        now=datetime.datetime(2026, 9, 27, 12, 0, tzinfo=datetime.timezone.utc))


def test_scan_findings_are_merged_with_extension_findings(case):
    c = codes(case)
    assert {"INF_NO_WAYBACK", "INF_TYPO_REGISTERED", "INF_TYPO_SAME_IP", "INF_ABUSE_IP", "INF_EXPOSED_PORTS",
            "INF_KNOWN_CVES", "INF_BREACHED_EMAIL", "INF_SANCTIONS_NAME", "INF_RELATED_DOMAINS"} <= c
    assert {"CODE_RANDOM_UPLOADED", "ONC_PASSTHROUGH_FLOW", "ECO_HIGH_RETURN"} <= c       # parte dell'estensione
    ids = [f.id for f in all_findings(case)]
    assert len(ids) == len(set(ids))                                                     # ID stabili e unici


def test_company_taken_from_scan_without_extra_arguments(case):
    assert case["entity"]["country"] == "PT"
    assert case["entity"]["query"]["vat"] == "PT500000000"


def test_extra_sections_and_email_masking(case):
    titles = [s["title"] for s in case["extra_sections"]]
    assert len(titles) == 4
    flat = str(case["extra_sections"])
    assert "support@arbitrage-demo.example" not in flat and "su***@arbitrage-demo.example" in flat


def test_severity_thresholds():
    scan = {"target": "x.example", "type": "domain",
            "abuseipdb": {"abuse_confidence_score": 90, "total_reports": 50},
            "exposed_ports": {"found": True, "open_ports": [80, 443]},
            "similar_domains": {"permutations_checked": 25, "registered_found": []}}
    fs = {f.code: f for f in bridge.scan_findings(scan)}
    assert fs["INF_ABUSE_IP"].severity == "high"
    assert "INF_EXPOSED_PORTS" not in fs and "INF_TYPO_REGISTERED" not in fs
    scan["abuseipdb"]["abuse_confidence_score"] = 10
    assert "INF_ABUSE_IP" not in {f.code for f in bridge.scan_findings(scan)}


def test_error_and_skipped_blocks_do_not_crash_or_create_findings():
    scan = {"target": "x.example", "type": "domain", "ip_info": {"error": "boom"},
            "abuseipdb": {"skipped": "no key"}, "subdomains": {"error": "crt.sh 502"},
            "wayback": {"has_any_snapshot": False, "_available_api_error": "timeout"},
            "darkweb": {"skipped": "no key"}, "exposed_ports": None, "reverse_ip": "garbage",
            "discovered_company_analysis": {"_note": "nessun CNPJ"}}
    assert bridge.scan_findings(scan) == []                 # un errore di rete non e' un indizio
    assert bridge.extra_sections(scan) == []


def test_cnpj_company_gets_official_incorporation_date():
    scan = {"target": "x.example", "type": "domain", "discovered_company_analysis": {"cnpj": {"11.222.333/0001-81": {
        "registry": {"razao_social": "EMPRESA TESTE LTDA", "data_inicio_atividade": "2026-05-01",
                     "situacao_cadastral": "ATIVA"}, "sanctions_screening": {}}}}}
    comp = bridge.company_from_scan(scan)
    assert comp["country"] == "BR" and comp["vat"] == "11222333000181" and comp["incorporated"] == "2026-05-01"


def test_non_domain_target_is_rejected():
    with pytest.raises(ValueError):
        bridge.case_from_scan({"target": "a@b.com", "type": "email"})


def test_english_render_with_extra_sections(case, tmp_path):
    pdf = str(tmp_path / "e.pdf")
    c = bridge.case_from_scan(demo.build_demo_scan(), demo.build_fake_http(), lang="en",
                              now=datetime.datetime(2026, 9, 27, tzinfo=datetime.timezone.utc))
    report.render(c, pdf, lang="en")
    import subprocess
    txt = subprocess.run(["pdftotext", "-layout", pdf, "-"], capture_output=True, text=True).stdout
    assert "Infrastructure, history and related networks" in txt and "Lookalike domains" in txt
