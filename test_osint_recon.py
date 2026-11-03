#!/usr/bin/env python3
"""
test_osint_recon.py - Suite di test automatici per osint_recon.py

Copre soprattutto le funzioni di PARSING/LOGICA PURA (niente chiamate di rete vere -
quelle sono mockate) - in particolare i bug reali trovati e corretti durante lo
sviluppo, per evitare che si ripresentino in futuro modificando il codice.

Uso:
    python3 test_osint_recon.py
    python3 -m unittest test_osint_recon -v

Nessuna dipendenza esterna oltre a quelle già richieste da osint_recon.py stesso
(usa solo unittest, incluso nella libreria standard di Python).
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import osint_recon as osr


class TestTargetDetection(unittest.TestCase):
    """Riconoscimento del tipo di target - deve restare inequivocabile."""

    def test_domain_is_default(self):
        self.assertFalse(osr.is_email_target("esempio.com"))
        self.assertFalse(osr.is_phone_target("esempio.com"))
        self.assertFalse(osr.is_cnpj_target("esempio.com"))
        self.assertFalse(osr.is_username_target("esempio.com"))  # contiene un punto

    def test_email(self):
        self.assertTrue(osr.is_email_target("nome@esempio.com"))
        self.assertFalse(osr.is_email_target("esempio.com"))

    def test_phone(self):
        self.assertTrue(osr.is_phone_target("+391234567890"))
        self.assertTrue(osr.is_phone_target("+5585999241424"))
        self.assertFalse(osr.is_phone_target("esempio.com"))

    def test_cnpj(self):
        self.assertTrue(osr.is_cnpj_target("42.469.602/0001-32"))
        self.assertTrue(osr.is_cnpj_target("42469602000132"))
        self.assertFalse(osr.is_cnpj_target("IT02117980405"))

    def test_piva(self):
        self.assertTrue(osr.is_piva_target("IT02117980405"))
        self.assertFalse(osr.is_piva_target("42.469.602/0001-32"))

    def test_username(self):
        self.assertTrue(osr.is_username_target("mario_rossi"))
        self.assertFalse(osr.is_username_target("mario.rossi"))  # il punto lo rende ambiguo con un dominio
        self.assertFalse(osr.is_username_target("123456"))  # solo cifre = potrebbe essere altro

    def test_sanitize_removes_invisible_chars(self):
        """Bug reale: caratteri Unicode invisibili (copia-incolla da messaggistica)
        rompevano il riconoscimento dei numeri di telefono."""
        raw = "\u202a+393497641475\u202c\u202c"
        clean = osr.sanitize_target(raw)
        self.assertEqual(clean, "+393497641475")
        self.assertTrue(osr.is_phone_target(clean))


class TestEmailFiltering(unittest.TestCase):
    """Filtro email: deve scartare rumore (pixel di tracciamento, placeholder)
    mantenendo le email reali."""

    def test_junk_sentry_pixel(self):
        self.assertTrue(osr.is_junk_email("18d2f96d279149989b95faf0a4b41882@sentry-next.wixpress.com"))

    def test_junk_placeholder(self):
        self.assertTrue(osr.is_junk_email("exemplo@meusite.com"))

    def test_real_email_not_junk(self):
        self.assertFalse(osr.is_junk_email("cliente@mcgbank.org"))
        self.assertFalse(osr.is_junk_email("sac@fazbank.com.br"))

    def test_extract_emails_clean_filters_noise(self):
        html = (
            "<p>18d2f96d279149989b95faf0a4b41882@sentry-next.wixpress.com</p>"
            "<p>cliente@mcgbank.org</p>"
            "<p>exemplo@meusite.com</p>"
        )
        result = osr.extract_emails_clean(html)
        self.assertEqual(result, ["cliente@mcgbank.org"])


class TestSocialMediaExtraction(unittest.TestCase):
    """Bug reale: i link social venivano cercati anche dentro <script>, catturando
    riferimenti generici del builder del sito (es. Wix) invece dei social veri."""

    def test_finds_real_footer_link(self):
        html = '<footer><a href="https://instagram.com/mcgbank_oficial">IG</a></footer>'
        result = osr.extract_social_media_links(html)
        self.assertEqual(result.get("instagram"), ["mcgbank_oficial"])

    def test_ignores_script_boilerplate(self):
        html = (
            '<footer><a href="https://instagram.com/mcgbank_oficial">IG</a></footer>'
            '<script>var repo = "https://github.com/wix/some-lib";</script>'
            '<script>var w = "https://twitter.com/bolt";</script>'
        )
        result = osr.extract_social_media_links(html)
        self.assertNotIn("github", result)  # 'wix' è rumore noto, filtrato
        self.assertNotIn("twitter_x", result)  # 'bolt' è rumore noto, filtrato
        self.assertEqual(result.get("instagram"), ["mcgbank_oficial"])

    def test_known_platform_noise_filtered_even_outside_script(self):
        """Anche se per qualche motivo 'wix'/'bolt' comparissero fuori da uno
        script, restano filtrati come rumore noto."""
        html = '<a href="https://github.com/wix">GH</a>'
        result = osr.extract_social_media_links(html)
        self.assertNotIn("github", result)


class TestCompanyIdExtraction(unittest.TestCase):
    def test_cnpj_and_piva_extraction(self):
        html = "P.IVA IT02117980405 - CNPJ: 42.469.602/0001-32"
        result = osr.extract_company_ids(html)
        self.assertIn("42.469.602/0001-32", result.get("cnpj", []))
        self.assertIn("IT02117980405", result.get("piva", []))


class TestGenericInfraFiltering(unittest.TestCase):
    """Bug reale: servizi di domain parking di massa (Sedo, Trellian, ParkLogic)
    venivano trattati come 'collegamento forte' nella correlazione."""

    def test_cloudflare_is_generic(self):
        self.assertTrue(osr.is_generic_infra("Cloudflare, Inc."))

    def test_sedo_is_generic(self):
        self.assertTrue(osr.is_generic_infra("Sedo GmbH"))

    def test_parklogic_is_generic(self):
        self.assertTrue(osr.is_generic_infra("ParkLogic Networks"))

    def test_dedicated_hosting_not_generic(self):
        self.assertFalse(osr.is_generic_infra("Business121 Dedicated Server LLC"))


class TestSociAdminFiltering(unittest.TestCase):
    """Bug reale (privacy): la correlazione trattava TUTTI i soci (anche i 74
    investitori non amministratori di MCG Lotteria) come collegamento forte."""

    def test_extract_fingerprints_only_admins(self):
        data = {
            "company_registry": {
                "found": True,
                "socios": [
                    {"nome": "ANA KELY BEZERRA LIMA", "qualificacao": "Sócio-Administrador"},
                    {"nome": "INVESTITORE UNO", "qualificacao": "Sócio"},
                    {"nome": "INVESTITORE DUE", "qualificacao": "Sócio"},
                ],
            }
        }
        strong, weak = osr.extract_fingerprints("test_target", data)
        names_found = [v for (t, v) in strong if t == "Amministratore societario"]
        self.assertIn("ANA KELY BEZERRA LIMA", names_found)
        self.assertNotIn("INVESTITORE UNO", names_found)
        self.assertNotIn("INVESTITORE DUE", names_found)


class TestWhoisEmailFiltering(unittest.TestCase):
    """Bug reale: email 'boilerplate' di registrar/registro (abuse@namecheap.com,
    cert@cert.br) venivano trattate come collegamento forte tra domini scollegati."""

    def test_generic_whois_emails_filtered(self):
        self.assertTrue(osr.is_generic_whois_email("abuse@namecheap.com"))
        self.assertTrue(osr.is_generic_whois_email("cert@cert.br"))

    def test_real_whois_email_not_filtered(self):
        self.assertFalse(osr.is_generic_whois_email("contato@evotrading.llc"))

    def test_extract_fingerprints_whois_owner(self):
        data = {"whois": {"raw": "owner: EvoTrading S/A\nowner-c: TISOU229"}}
        strong, weak = osr.extract_fingerprints("lotto10.com.br", data)
        owners = [v for (t, v) in strong if t == "WHOIS owner/person"]
        self.assertIn("EVOTRADING S/A", owners)


class TestIdentifyLeadsFairness(unittest.TestCase):
    """Bug reale: 3 domini typosquat esaurivano da soli il limite di diramazioni
    (max_leads), impedendo a domini/username scoperti altrove di essere seguiti."""

    def _build_data(self):
        return {
            "similar_domains": {"registered_found": [
                {"domain": "x-app.com", "resolved_ip": "1.1.1.1"},
                {"domain": "x-login.com", "resolved_ip": "1.1.1.2"},
                {"domain": "x-official.com", "resolved_ip": "1.1.1.3"},
            ]},
            "http_fingerprint": {"emails_found": ["contatto@altrobrand.com"], "social_links_found": {}},
            "additional_pages": {"emails_found": [], "social_links_found": {}},
            "social_profiles_found": {"instagram": ["handle_ufficiale"]},
            "discovered_company_analysis": {},
            "subdomains": {}, "reverse_ip": {},
        }

    def test_round_robin_gives_diversity_even_with_low_cap(self):
        data = self._build_data()
        leads = osr.identify_leads(data, "target.com", "domain", max_leads=3)
        types_found = set(l["target"] for l in leads)
        self.assertFalse(
            types_found.issubset({"x-app.com", "x-login.com", "x-official.com"}),
            "i typosquat non devono saturare da soli tutte le diramazioni disponibili"
        )

    def test_public_email_provider_not_a_lead(self):
        data = self._build_data()
        data["http_fingerprint"]["emails_found"] = ["qualcuno@gmail.com"]
        leads = osr.identify_leads(data, "target.com", "domain", max_leads=10)
        targets = [l["target"] for l in leads]
        self.assertNotIn("gmail.com", targets)

    def test_email_domain_becomes_lead(self):
        data = self._build_data()
        leads = osr.identify_leads(data, "target.com", "domain", max_leads=10)
        targets = [l["target"] for l in leads]
        self.assertIn("altrobrand.com", targets)


class TestDomainPermutations(unittest.TestCase):
    def test_generates_plausible_variants(self):
        perms = osr.generate_domain_permutations("esempio.com.br")
        self.assertTrue(len(perms) > 0)
        self.assertNotIn("esempio.com.br", perms)


class TestDiffModule(unittest.TestCase):
    """Modalità --diff: deve rilevare correttamente i cambiamenti tra due scansioni."""

    def test_detects_new_email(self):
        old = {"http_fingerprint": {"emails_found": ["a@x.com"]}}
        new = {"http_fingerprint": {"emails_found": ["a@x.com", "b@x.com"]}}
        diff = osr.compute_diff(old, new)
        self.assertIn("email_nel_sito", diff["changes"])
        self.assertEqual(diff["changes"]["email_nel_sito"]["aggiunti"], ["b@x.com"])

    def test_detects_ip_change(self):
        old = {"ip_info": {"resolved_ip": "1.2.3.4"}}
        new = {"ip_info": {"resolved_ip": "5.6.7.8"}}
        diff = osr.compute_diff(old, new)
        self.assertEqual(diff["changes"]["ip"], {"prima": "1.2.3.4", "ora": "5.6.7.8"})

    def test_no_changes_gives_empty_diff(self):
        data = {"ip_info": {"resolved_ip": "1.2.3.4"}, "http_fingerprint": {"emails_found": ["a@x.com"]}}
        diff = osr.compute_diff(data, dict(data))
        self.assertEqual(diff["changes"], {})


class TestConfigSystem(unittest.TestCase):
    """Sistema di configurazione (--setup): le chiavi devono essere lette con la
    priorità corretta (ambiente prima, poi file di configurazione)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.orig_config_dir = osr.CONFIG_DIR
        self.orig_config_path = osr.CONFIG_PATH
        osr.CONFIG_DIR = self.tmpdir
        osr.CONFIG_PATH = os.path.join(self.tmpdir, "config.json")

    def tearDown(self):
        osr.CONFIG_DIR = self.orig_config_dir
        osr.CONFIG_PATH = self.orig_config_path
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        os.environ.pop("TEST_DUMMY_KEY", None)

    def test_save_and_load_config(self):
        osr.save_config({"GOOGLE_API_KEY": "abc123"})
        loaded = osr.load_config()
        self.assertEqual(loaded.get("GOOGLE_API_KEY"), "abc123")

    def test_env_var_takes_priority_over_config(self):
        osr.save_config({"TEST_DUMMY_KEY": "da_config"})
        os.environ["TEST_DUMMY_KEY"] = "da_env"
        self.assertEqual(osr.get_api_key("TEST_DUMMY_KEY"), "da_env")

    def test_config_used_when_no_env_var(self):
        osr.save_config({"TEST_DUMMY_KEY": "da_config"})
        self.assertEqual(osr.get_api_key("TEST_DUMMY_KEY"), "da_config")

    def test_missing_key_returns_none(self):
        self.assertIsNone(osr.get_api_key("CHIAVE_MAI_IMPOSTATA"))


class TestCheckpointResume(unittest.TestCase):
    """Modalità --resume: i nodi già completati vanno ricaricati dalla cache,
    non ri-scansionati."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_checkpoint_save_and_load(self):
        osr.save_checkpoint("root.com", self.tmpdir, {"root.com", "child.com"}, 2, 3, False)
        cp = osr.load_checkpoint("root.com", self.tmpdir)
        self.assertIsNotNone(cp)
        self.assertEqual(set(cp["visited"]), {"root.com", "child.com"})

    def test_clear_checkpoint(self):
        osr.save_checkpoint("root.com", self.tmpdir, {"root.com"}, 2, 3, False)
        osr.clear_checkpoint("root.com", self.tmpdir)
        self.assertIsNone(osr.load_checkpoint("root.com", self.tmpdir))

    def test_resume_skips_cached_scan(self):
        call_log = []

        def fake_dispatch(target, target_type, do_analyze):
            call_log.append(target)
            return {
                "scanned_at": "x", "similar_domains": {}, "subdomains": {}, "reverse_ip": {},
                "discovered_company_analysis": {}, "http_fingerprint": {}, "additional_pages": {},
                "social_profiles_found": {},
            }

        with patch.object(osr, "dispatch_scan", fake_dispatch), \
             patch.object(osr, "write_report", lambda data, target, output_dir: (f"{target}.json", f"{target}.txt")), \
             patch.object(osr, "load_cached_scan", lambda target, output_dir: (
                 {"scanned_at": "x", "similar_domains": {}, "subdomains": {}, "reverse_ip": {},
                  "discovered_company_analysis": {}, "http_fingerprint": {}, "additional_pages": {},
                  "social_profiles_found": {}} if target == "root.com" else None
             )):
            osr.investigate_recursive("root.com", "domain", 1, 3, False, self.tmpdir)
            self.assertIn("root.com", call_log)

            call_log.clear()
            tree = osr.investigate_recursive("root.com", "domain", 1, 3, False, self.tmpdir, resume_cache={"root.com"})
            self.assertNotIn("root.com", call_log)
            self.assertTrue(tree.get("from_cache"))


class TestMarkdownReport(unittest.TestCase):
    def test_generates_basic_report(self):
        data = {
            "target": "esempio.com", "type": "domain", "scanned_at": "2026-01-01",
            "ip_info": {"resolved_ip": "1.2.3.4", "isp": "Test ISP", "country": "IT"},
            "whois": {"raw": "owner: TEST OWNER"},
            "http_fingerprint": {"emails_found": ["a@esempio.com"]},
        }
        md = osr.generate_markdown_report(data)
        self.assertIn("esempio.com", md)
        self.assertIn("1.2.3.4", md)
        self.assertIn("TEST OWNER", md)
        self.assertIn("a@esempio.com", md)


try:
    import reportlab  # noqa: F401
    HAS_REPORTLAB = True
except Exception:       # ImportError, ma anche il RuntimeError/ImportError di versioni incompatibili con il Python in uso
    HAS_REPORTLAB = False


class TestForensicPdfIntegration(unittest.TestCase):
    """Integrazione con osintr_ext (--pdf): tutto offline, con client HTTP finto e dati sintetici."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _args(self, **kw):
        import argparse
        base = dict(pdf="auto", pdf_lang="it", pdf_no_redact=False, pdf_ofac=False, tx=None, tx_chain="bsc",
                    evidence=None, analyst="Test", case_ref="T-1", reporter_country="IT")
        base.update(kw)
        return argparse.Namespace(**base)

    def test_resolve_pdf_path(self):
        self.assertEqual(osr.resolve_pdf_path("mio.pdf", "x.com", self.tmp), "mio.pdf")
        auto = osr.resolve_pdf_path("auto", "x.com", self.tmp)
        self.assertTrue(auto.startswith(self.tmp) and auto.endswith(".pdf") and "x.com_" in auto)

    def test_non_domain_target_is_refused_without_crashing(self):
        out = osr.generate_forensic_pdf({"type": "email", "target": "a@b.com"}, os.path.join(self.tmp, "x.pdf"), self._args())
        self.assertIsNone(out)

    def test_missing_package_is_reported_not_raised(self):
        with patch.dict(sys.modules, {"osintr_ext": None, "osintr_ext.bridge": None, "osintr_ext.report": None}):
            out = osr.generate_forensic_pdf({"type": "domain", "target": "x.com"}, os.path.join(self.tmp, "x.pdf"), self._args())
        self.assertIsNone(out)

    @unittest.skipUnless(HAS_REPORTLAB, "reportlab non utilizzabile con questo Python: pip install \"reportlab<5\"")
    def test_end_to_end_pdf_with_fake_network(self):
        from osintr_ext import demo
        pdf = os.path.join(self.tmp, "r.pdf")
        with patch("osintr_ext.util.Http", side_effect=lambda *a, **k: demo.build_fake_http()):
            out = osr.generate_forensic_pdf(demo.build_demo_scan(), pdf, self._args(tx=demo.TX))
        self.assertEqual(out, pdf)
        with open(pdf, "rb") as f:
            head = f.read(5)
        self.assertEqual(head, b"%PDF-")
        self.assertGreater(os.path.getsize(pdf), 10_000)
        case_json = os.path.join(self.tmp, "r_caso.json")
        self.assertTrue(os.path.exists(case_json))
        with open(case_json, encoding="utf-8") as f:
            case = json.load(f)
        self.assertEqual(case["assessment"]["level"], "critical")
        self.assertTrue(any(f["code"] == "INF_TYPO_SAME_IP" for f in case["findings"]))

    def test_progress_messages_printed_during_scan(self):
        from osintr_ext import demo
        with patch("osintr_ext.util.Http", side_effect=lambda *a, **k: demo.build_fake_http()):
            with patch("builtins.print") as mp:
                osr.generate_forensic_pdf(demo.build_demo_scan(), os.path.join(self.tmp, "r2.pdf"),
                                          self._args(tx=demo.TX))
        printed = " ".join(str(c.args[0]) for c in mp.call_args_list if c.args)
        self.assertIn("Analisi del sito", printed)

    def test_pdf_vat_country_incorporated_flags_are_passed_to_the_bridge(self):
        from osintr_ext import demo
        args = self._args(pdf_vat="PT519515471", pdf_country="PT", pdf_incorporated="2026-07-01")
        with patch("osintr_ext.bridge.case_from_scan", side_effect=RuntimeError("stop")) as m:
            osr.generate_forensic_pdf(demo.build_demo_scan(), "/tmp/x.pdf", args)
        assert m.call_args.kwargs["vat"] == "PT519515471"
        assert m.call_args.kwargs["country"] == "PT"
        assert m.call_args.kwargs["incorporated"] == "2026-07-01"

    def test_pdf_vat_country_default_to_none_when_not_given(self):
        from osintr_ext import demo
        args = self._args()
        for k in ("pdf_vat", "pdf_country", "pdf_incorporated"):
            if hasattr(args, k):
                delattr(args, k)
        with patch("osintr_ext.bridge.case_from_scan", side_effect=RuntimeError("stop")) as m:
            osr.generate_forensic_pdf(demo.build_demo_scan(), "/tmp/x.pdf", args)
        assert m.call_args.kwargs["vat"] is None and m.call_args.kwargs["country"] is None

    def test_no_discover_flag_is_passed_to_the_bridge(self):
        from osintr_ext import demo
        for flag, expected in (([], True), (["x"], False)):
            args = self._args(pdf_no_discover=bool(flag))
            with patch("osintr_ext.bridge.case_from_scan", side_effect=RuntimeError("stop")) as m:
                osr.generate_forensic_pdf(demo.build_demo_scan(), os.path.join(self.tmp, "x.pdf"), args)
            self.assertEqual(m.call_args.kwargs["discover"], expected)

    def test_pdf_failure_never_raises(self):
        with patch("osintr_ext.bridge.case_from_scan", side_effect=RuntimeError("boom")):
            out = osr.generate_forensic_pdf({"type": "domain", "target": "x.com"}, os.path.join(self.tmp, "x.pdf"), self._args())
        self.assertIsNone(out)

    def _run_main(self, argv, scan=None):
        scan = scan or {"type": "domain", "target": "x.example", "scanned_at": "2026-01-01T00:00:00+00:00"}
        with patch.object(sys, "argv", ["osintr"] + argv), \
                patch.object(osr, "dispatch_scan", return_value=scan), \
                patch.object(osr, "generate_forensic_pdf", return_value="ok") as gen:
            osr.main()
        return gen

    def test_flag_pdf_triggers_generation_only_when_requested(self):
        gen = self._run_main(["x.example", "--no-analyze", "--output", self.tmp, "--pdf", os.path.join(self.tmp, "a.pdf")])
        self.assertEqual(gen.call_count, 1)
        self.assertEqual(gen.call_args[0][1], os.path.join(self.tmp, "a.pdf"))
        gen = self._run_main(["x.example", "--no-analyze", "--output", self.tmp])
        self.assertEqual(gen.call_count, 0)

    def test_flag_pdf_without_value_uses_output_folder(self):
        gen = self._run_main(["x.example", "--no-analyze", "--output", self.tmp, "--pdf"])
        self.assertTrue(gen.call_args[0][1].startswith(self.tmp))

    def test_report_json_with_pdf_regenerates_from_saved_scan(self):
        saved = os.path.join(self.tmp, "saved.json")
        with open(saved, "w", encoding="utf-8") as f:
            json.dump({"type": "domain", "target": "x.example"}, f)
        with patch.object(sys, "argv", ["osintr", "--report", saved, "--output", self.tmp, "--pdf", "--pdf-lang", "en"]), \
                patch.object(osr, "run_report_generation"), \
                patch.object(osr, "generate_forensic_pdf", return_value="ok") as gen:
            osr.main()
        self.assertEqual(gen.call_count, 1)
        self.assertEqual(gen.call_args[0][0]["target"], "x.example")
        self.assertEqual(gen.call_args[0][2].pdf_lang, "en")


class TestNetworkReport(unittest.TestCase):
    """--targets / --pdf-network: scansione multi-target con tipi misti e rapporto combinato."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _args(self, **kw):
        import argparse
        base = dict(pdf_lang="it", pdf_no_redact=False, pdf_ofac=False, analyst="Test", pdf_no_discover=False,
                   no_analyze=True, min_shared=2, output=self.tmp)
        base.update(kw)
        return argparse.Namespace(**base)

    def test_classify_target_matches_main_logic(self):
        self.assertEqual(osr.classify_target("mario@esempio.com"), "email")
        self.assertEqual(osr.classify_target("11.222.333/0001-81"), "cnpj")
        self.assertEqual(osr.classify_target("esempio.com"), "domain")

    def test_requires_at_least_two_successful_scans(self):
        from osintr_ext import demo
        scan = demo.build_demo_scan()
        with patch.object(osr, "dispatch_scan", return_value=scan), \
                patch("osintr_ext.bridge.case_from_scan", return_value={"assessment": {"level": "low"},
                                                                         "wallets": [], "entity": None}):
            out = osr.run_network_scan(["unico.example"], os.path.join(self.tmp, "r.pdf"), self._args())
        self.assertIsNone(out)

    def test_failed_scan_is_excluded_not_fatal(self):
        from osintr_ext import demo
        good = demo.build_demo_scan()
        good["target"] = "ok.example"
        bad = demo.build_demo_scan()
        bad["target"] = "altro.example"
        third = demo.build_demo_scan()
        third["target"] = "ok2.example"

        def fake_dispatch(target, ttype, do_analyze):
            if target == "altro.example":
                return {"error": "boom"}
            return {"ok.example": good, "ok2.example": third}[target]

        with patch.object(osr, "dispatch_scan", side_effect=fake_dispatch), \
                patch("osintr_ext.bridge.case_from_scan", return_value={"assessment": {"level": "low"},
                                                                         "wallets": [], "entity": None}):
            out = osr.run_network_scan(["ok.example", "altro.example", "ok2.example"],
                                       os.path.join(self.tmp, "r.pdf"), self._args())
        self.assertEqual(out, os.path.join(self.tmp, "r.pdf"))

    def test_mixed_types_and_shared_wallet_produce_one_combined_pdf(self):
        from osintr_ext import demo
        a = demo.build_demo_scan(); a["target"] = "sito-a.example"
        a["http_fingerprint"]["crypto_addresses_found"] = {"bitcoin": ["bc1qSHARED"]}
        b = demo.build_demo_scan(); b["target"] = "sito-b.example"
        b["http_fingerprint"]["crypto_addresses_found"] = {"bitcoin": ["bc1qSHARED"]}

        def fake_dispatch(target, ttype, do_analyze):
            if target == "sito-a.example":
                self.assertEqual(ttype, "domain")
                return a
            if target == "sito-b.example":
                return b
            if target == "mario@esempio.com":
                self.assertEqual(ttype, "email")
                return {"type": "email", "target": target}
            raise AssertionError(f"target inatteso: {target}")

        from osintr_ext.bridge import case_from_scan as real_case_from_scan
        from osintr_ext import demo as ext_demo

        def fake_case_from_scan(data, http=None, **kw):
            return real_case_from_scan(data, ext_demo.build_fake_http(), **kw)

        pdf = os.path.join(self.tmp, "rete.pdf")
        with patch.object(osr, "dispatch_scan", side_effect=fake_dispatch), \
                patch("osintr_ext.bridge.case_from_scan", side_effect=fake_case_from_scan):
            out = osr.run_network_scan(["sito-a.example", "sito-b.example", "mario@esempio.com"], pdf, self._args())
        self.assertEqual(out, pdf)
        with open(pdf, "rb") as f:
            self.assertEqual(f.read(5), b"%PDF-")
        saved = [f for f in os.listdir(self.tmp) if f.startswith("sito-a.example_") and f.endswith(".json")]
        self.assertTrue(saved, "il report JSON individuale di sito-a.example non è stato salvato")
        corr_json = os.path.join(self.tmp, "rete_correlazioni.json")
        self.assertTrue(os.path.exists(corr_json))
        with open(corr_json, encoding="utf-8") as f:
            corr = json.load(f)
        kinds = {c["type"] for c in corr["correlations"]}
        self.assertIn("Wallet bitcoin", kinds)

    def test_ofac_list_is_downloaded_once_not_per_target(self):
        """Regressione: prima scaricava la lista OFAC ad ogni target invece che una sola volta."""
        from osintr_ext import demo
        a = demo.build_demo_scan(); a["target"] = "sito-a.example"
        b = demo.build_demo_scan(); b["target"] = "sito-b.example"

        def fake_dispatch(target, ttype, do_analyze):
            return {"sito-a.example": a, "sito-b.example": b}[target]

        from osintr_ext.bridge import case_from_scan as real_case_from_scan
        from osintr_ext import demo as ext_demo

        def fake_case_from_scan(data, http=None, **kw):
            return real_case_from_scan(data, ext_demo.build_fake_http(), **kw)

        with patch.object(osr, "dispatch_scan", side_effect=fake_dispatch), \
                patch("osintr_ext.bridge.case_from_scan", side_effect=fake_case_from_scan), \
                patch("osintr_ext.chains.Blocklists.load_ofac", return_value=True) as m:
            osr.run_network_scan(["sito-a.example", "sito-b.example"], os.path.join(self.tmp, "r.pdf"),
                                 self._args(pdf_ofac=True))
        self.assertEqual(m.call_count, 1)

    def test_cli_targets_flag_dispatches_to_network_scan(self):
        with patch.object(sys, "argv", ["osintr", "--targets", "a.example", "b.example",
                                        "--pdf-network", os.path.join(self.tmp, "r.pdf")]), \
                patch.object(osr, "run_network_scan", return_value="ok") as m:
            osr.main()
        self.assertEqual(m.call_args[0][0], ["a.example", "b.example"])
        self.assertEqual(m.call_args[0][1], os.path.join(self.tmp, "r.pdf"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
