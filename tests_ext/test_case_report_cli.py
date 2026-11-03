import json
import subprocess
import sys

import pytest

pytest.importorskip("reportlab", reason='pip install "reportlab<5"')

from osintr_ext import cli, report
from osintr_ext.case import all_findings
from osintr_ext.demo import WC, build_demo_case


@pytest.fixture(scope="module")
def case():
    return build_demo_case("it")


def codes(c):
    return {f.code for f in all_findings(c)}


def test_demo_case_pipeline(case):
    assert case["assessment"]["level"] == "critical"
    assert {"CODE_RANDOM_UPLOADED", "ECO_HIGH_RETURN", "ECO_INCONSISTENT", "ONC_PASSTHROUGH_FLOW", "DOM_YOUNG",
            "ENT_RECENT_INCORP", "WEB_LEGAL_MISSING", "ENT_VAT_OK"} <= codes(case)
    assert [h["to_type"] for h in case["flow"]["hops"]] == ["EOA", "EOA"]
    assert case["entity"]["country"] == "PT" and case["entity"]["verification_sources"]
    assert len(case["wallets"]) == 4 and case["evidence"][0]["name"] == "screenshot_originale_demo.png"
    json.dumps(case)   # serializzabile


def test_geo_section_renders_in_both_languages(case, tmp_path):
    for lang, needle in (("it", "Verifica geografica dell'indirizzo"), ("en", "Geographic verification")):
        pdf = str(tmp_path / f"geo_{lang}.pdf")
        report.render(case, pdf, lang=lang)
        assert needle in text_of(pdf)


def test_endpoint_table_shows_categories_and_login_marker(case, tmp_path):
    pdf = str(tmp_path / "c.pdf")
    report.render(case, pdf)
    t = text_of(pdf)
    assert "wallet_saldo" in t and "(login)" in t


def test_demo_finds_hidden_endpoint_address_and_reports_it(case):
    from osintr_ext.demo import WD
    assert "ONC_ADDR_FROM_ENDPOINT" in codes(case)
    assert WD.lower() in {w["address"].lower() for w in case["wallets"]}
    assert any(e["url"].endswith("/api/finance") for e in case["site"]["endpoints"])


def test_rates_in_demo_are_not_mixed_up(case):
    got = {(r["rate"], r["period"]) for r in case["site"]["text"]["rates"]}
    assert got == {(5.0, "monthly"), (1.2, "daily")}


def text_of(pdf):
    out = subprocess.run(["pdftotext", "-layout", pdf, "-"], capture_output=True, text=True, check=True).stdout
    return out


@pytest.mark.parametrize("lang,needle", [("it", "RAPPORTO TECNICO-FORENSE"), ("en", "TECHNICAL-FORENSIC REPORT")])
def test_pdf_renders_both_languages(tmp_path, lang, needle):
    c = build_demo_case(lang)
    pdf = str(tmp_path / f"r_{lang}.pdf")
    report.render(c, pdf, lang=lang, redact=True)
    t = text_of(pdf)
    assert needle in t and "arbitrage-demo.example".upper() in t
    assert "1.500,99" in t if lang == "it" else "1,500.99" in t


def test_redaction_hides_full_addresses_unless_disabled(tmp_path, case):
    red, full = str(tmp_path / "red.pdf"), str(tmp_path / "full.pdf")
    report.render(case, red, redact=True)
    report.render(case, full, redact=False)
    flat = lambda p: text_of(p).replace("\n", "").replace(" ", "")
    assert WC.lower() not in flat(red).lower()
    assert WC.lower() in flat(full).lower()


def test_manual_finding_is_rendered(tmp_path, case):
    pdf = str(tmp_path / "m.pdf")
    report.render(case, pdf)
    assert "Prelievo non disponibile" in text_of(pdf)


def test_cli_selftest_and_report_roundtrip(tmp_path):
    pdf, js = str(tmp_path / "e.pdf"), str(tmp_path / "e.json")
    assert cli.main(["selftest", "--pdf", pdf, "--json", js]) == 0
    pdf2 = str(tmp_path / "again.pdf")
    assert cli.main(["report", js, "--pdf", pdf2, "--lang", "en"]) == 0
    assert "TECHNICAL-FORENSIC REPORT" in text_of(pdf2)


def test_cli_addr_rejects_unknown_format(capsys):
    assert cli.main(["addr", "not-an-address"]) == 1
    assert "non riconosciuto" in capsys.readouterr().out


def test_cli_case_requires_a_target(capsys):
    assert cli.main(["case"]) == 2


def test_plain_language_summary_present_in_both_languages(case):
    import subprocess
    for lang, title, closing in (("it", "In parole semplici", "Questa sintesi semplifica"),
                                 ("en", "In plain language", "This summary simplifies")):
        pdf = f"/tmp/_plain_{lang}.pdf"
        report.render(case, pdf, lang=lang)
        txt = subprocess.run(["pdftotext", "-layout", pdf, "-"], capture_output=True, text=True).stdout
        assert title in txt and closing in txt
        # la sintesi semplice deve comparire PRIMA della matrice tecnica "Perché il giudizio è forte" / "Why the assessment"
        why = "Perché il giudizio è forte" if lang == "it" else "Why the assessment is strong"
        assert txt.index(title) < txt.index(why)
