"""Directory di registri societari ufficiali e liste di avvisi delle autorità, per paese (ISO 3166-1 alpha-2).

Non fa scraping: serve a indicare all'analista *dove* verificare in modo formale un'entità, in qualsiasi paese.
Gli URL sono le home page istituzionali; vanno ricontrollati prima dell'uso in sede legale.
"""
from __future__ import annotations

from typing import Optional

# Voci globali, valide per qualsiasi paese
GLOBAL_SOURCES = [
    ("IOSCO I-SCAN (avvisi di oltre 100 autorità)", "https://www.iosco.org/i-scan/"),
    ("GLEIF - ricerca LEI", "https://search.gleif.org/"),
    ("OpenCorporates", "https://opencorporates.com/"),
    ("OpenSanctions", "https://www.opensanctions.org/"),
    ("OFAC Sanctions List Search", "https://sanctionssearch.ofac.treas.gov/"),
    ("EU Financial Sanctions (FSF)", "https://www.sanctionsmap.eu/"),
]

# country -> (nome, registro imprese / ente, autorità finanziaria + lista avvisi)
COUNTRIES: dict[str, dict] = {
    "IT": {"name": "Italia", "registry": ("Registro Imprese (InfoCamere)", "https://www.registroimprese.it/"),
           "regulator": ("Consob - avvisi ai risparmiatori", "https://www.consob.it/web/area-pubblica/avvisi-ai-risparmiatori"),
           "also": [("OAM - Organismo Agenti e Mediatori (VASP)", "https://www.organismo-am.it/")]},
    "ES": {"name": "España", "registry": ("Registro Mercantil Central", "https://www.rmc.es/"),
           "regulator": ("CNMV - advertencias al público", "https://www.cnmv.es/portal/Consultas/Listado-advertencias.aspx"),
           "also": [("Banco de España - registro de proveedores de cripto", "https://www.bde.es/")]},
    "PT": {"name": "Portugal", "registry": ("Registo Comercial / Portal da Empresa", "https://www.portaldaempresa.pt/"),
           "regulator": ("CMVM - alertas", "https://www.cmvm.pt/"),
           "also": [("Banco de Portugal - registo de ativos virtuais", "https://www.bportugal.pt/")]},
    "FR": {"name": "France", "registry": ("Infogreffe / Annuaire des Entreprises", "https://annuaire-entreprises.data.gouv.fr/"),
           "regulator": ("AMF - listes noires", "https://www.amf-france.org/fr/espace-epargnants/proteger-son-epargne/listes-noires-et-mises-en-garde")},
    "DE": {"name": "Deutschland", "registry": ("Handelsregister", "https://www.handelsregister.de/"),
           "regulator": ("BaFin - Verbraucherwarnungen", "https://www.bafin.de/DE/Verbraucher/Verbraucher_node.html")},
    "NL": {"name": "Nederland", "registry": ("KvK Handelsregister", "https://www.kvk.nl/"),
           "regulator": ("AFM - waarschuwingslijst", "https://www.afm.nl/nl-nl/consumenten/")},
    "BE": {"name": "Belgique/België", "registry": ("BCE/KBO", "https://kbopub.economie.fgov.be/"),
           "regulator": ("FSMA - mises en garde", "https://www.fsma.be/")},
    "IE": {"name": "Ireland", "registry": ("CRO", "https://core.cro.ie/"),
           "regulator": ("Central Bank - unauthorised firms", "https://www.centralbank.ie/consumer-hub/warnings")},
    "GB": {"name": "United Kingdom", "registry": ("Companies House", "https://find-and-update.company-information.service.gov.uk/"),
           "regulator": ("FCA - Warning List", "https://www.fca.org.uk/scamsmart/warning-list")},
    "CH": {"name": "Schweiz/Suisse", "registry": ("Zefix", "https://www.zefix.ch/"),
           "regulator": ("FINMA - warning list", "https://www.finma.ch/en/finma-public/warning-list/")},
    "AT": {"name": "Österreich", "registry": ("Firmenbuch", "https://www.justiz.gv.at/"),
           "regulator": ("FMA - Warnungen", "https://www.fma.gv.at/")},
    "LU": {"name": "Luxembourg", "registry": ("RCS Luxembourg", "https://www.lbr.lu/"),
           "regulator": ("CSSF - warnings", "https://www.cssf.lu/en/warnings/")},
    "MT": {"name": "Malta", "registry": ("Malta Business Registry", "https://mbr.mt/"),
           "regulator": ("MFSA - public warnings", "https://www.mfsa.mt/")},
    "CY": {"name": "Cyprus", "registry": ("Dept. of Registrar of Companies", "https://efiling.drcor.mcit.gov.cy/"),
           "regulator": ("CySEC - warnings", "https://www.cysec.gov.cy/en-GB/public-info/warnings/")},
    "LT": {"name": "Lietuva", "registry": ("Registrų centras", "https://www.registrucentras.lt/"),
           "regulator": ("Lietuvos bankas - warnings", "https://www.lb.lt/")},
    "EE": {"name": "Eesti", "registry": ("e-Business Register", "https://ariregister.rik.ee/"),
           "regulator": ("Finantsinspektsioon", "https://www.fi.ee/")},
    "PL": {"name": "Polska", "registry": ("KRS", "https://ekrs.ms.gov.pl/"),
           "regulator": ("KNF - ostrzeżenia", "https://www.knf.gov.pl/dla_konsumenta/ostrzezenia_publiczne")},
    "CZ": {"name": "Česko", "registry": ("Obchodní rejstřík", "https://or.justice.cz/"),
           "regulator": ("ČNB - varování", "https://www.cnb.cz/")},
    "SE": {"name": "Sverige", "registry": ("Bolagsverket", "https://bolagsverket.se/"),
           "regulator": ("Finansinspektionen - varningslista", "https://www.fi.se/")},
    "DK": {"name": "Danmark", "registry": ("CVR", "https://datacvr.virk.dk/"),
           "regulator": ("Finanstilsynet - warnings", "https://www.finanstilsynet.dk/")},
    "NO": {"name": "Norge", "registry": ("Brønnøysundregistrene", "https://www.brreg.no/"),
           "regulator": ("Finanstilsynet - advarsler", "https://www.finanstilsynet.no/")},
    "FI": {"name": "Suomi", "registry": ("PRH / YTJ", "https://www.ytj.fi/"),
           "regulator": ("FIN-FSA - warnings", "https://www.finanssivalvonta.fi/")},
    "GR": {"name": "Ελλάδα", "registry": ("GEMI", "https://www.businessportal.gr/"),
           "regulator": ("HCMC - warnings", "https://www.hcmc.gr/")},
    "US": {"name": "United States", "registry": ("SEC EDGAR + Secretary of State del singolo Stato", "https://www.sec.gov/edgar/search/"),
           "regulator": ("FINRA BrokerCheck / SEC / CFTC", "https://brokercheck.finra.org/"),
           "also": [("FinCEN - MSB Registrant Search", "https://www.fincen.gov/msb-registrant-search"),
                    ("FTC Consumer Sentinel / IC3 (FBI)", "https://www.ic3.gov/")]},
    "CA": {"name": "Canada", "registry": ("Corporations Canada + registri provinciali", "https://ised-isde.canada.ca/cc/lgcy/fdrlCrpSrch.html"),
           "regulator": ("CSA - Investor alerts", "https://www.securities-administrators.ca/")},
    "MX": {"name": "México", "registry": ("RPC / Registro Público de Comercio", "https://rpc.economia.gob.mx/"),
           "regulator": ("CNBV - listado de entidades no autorizadas", "https://www.gob.mx/cnbv")},
    "BR": {"name": "Brasil", "registry": ("Receita Federal - consulta CNPJ", "https://solucoes.receita.fazenda.gov.br/Servicos/cnpjreva/Cnpjreva_Solicitacao.asp"),
           "regulator": ("CVM - alertas", "https://www.gov.br/cvm/pt-br/assuntos/noticias"),
           "also": [("Banco Central do Brasil - instituições autorizadas", "https://www.bcb.gov.br/")]},
    "AR": {"name": "Argentina", "registry": ("Inspección General de Justicia", "https://www.argentina.gob.ar/justicia/igj"),
           "regulator": ("CNV - alertas", "https://www.argentina.gob.ar/cnv")},
    "CL": {"name": "Chile", "registry": ("Registro de Empresas y Sociedades", "https://www.registrodeempresasysociedades.cl/"),
           "regulator": ("CMF - alertas", "https://www.cmfchile.cl/")},
    "CO": {"name": "Colombia", "registry": ("RUES", "https://www.rues.org.co/"),
           "regulator": ("Superfinanciera - alertas", "https://www.superfinanciera.gov.co/")},
    "AU": {"name": "Australia", "registry": ("ASIC Connect / ABN Lookup", "https://abr.business.gov.au/"),
           "regulator": ("ASIC - investor alert list", "https://asic.gov.au/online-services/search-asics-registers/")},
    "NZ": {"name": "New Zealand", "registry": ("NZ Companies Office", "https://companies-register.companiesoffice.govt.nz/"),
           "regulator": ("FMA - warnings", "https://www.fma.govt.nz/")},
    "SG": {"name": "Singapore", "registry": ("ACRA BizFile+", "https://www.acra.gov.sg/"),
           "regulator": ("MAS - Investor Alert List", "https://www.mas.gov.sg/investor-alert-list")},
    "HK": {"name": "Hong Kong", "registry": ("Companies Registry", "https://www.cr.gov.hk/"),
           "regulator": ("SFC - Suspicious websites/entities", "https://www.sfc.hk/en/Alerts")},
    "JP": {"name": "日本", "registry": ("Corporate Number Publication Site", "https://www.houjin-bangou.nta.go.jp/"),
           "regulator": ("FSA - unregistered firms", "https://www.fsa.go.jp/en/")},
    "KR": {"name": "대한민국", "registry": ("Korea Business Registry", "https://www.iros.go.kr/"),
           "regulator": ("FSS - warnings", "https://english.fss.or.kr/")},
    "IN": {"name": "India", "registry": ("MCA - company master data", "https://www.mca.gov.in/"),
           "regulator": ("SEBI - investor alerts", "https://www.sebi.gov.in/")},
    "AE": {"name": "United Arab Emirates", "registry": ("Registri per free zone / Dept. of Economy", "https://www.moec.gov.ae/"),
           "regulator": ("SCA / DFSA / VARA - elenchi", "https://www.sca.gov.ae/")},
    "TR": {"name": "Türkiye", "registry": ("MERSIS", "https://mersis.gtb.gov.tr/"),
           "regulator": ("SPK - uyarılar", "https://www.spk.gov.tr/")},
    "ZA": {"name": "South Africa", "registry": ("CIPC", "https://www.cipc.co.za/"),
           "regulator": ("FSCA - warnings", "https://www.fsca.co.za/Regulatory-Frameworks/Pages/Warnings.aspx")},
    "NG": {"name": "Nigeria", "registry": ("CAC", "https://search.cac.gov.ng/"),
           "regulator": ("SEC Nigeria - public notices", "https://sec.gov.ng/")},
    "SC": {"name": "Seychelles", "registry": ("FSA Seychelles", "https://www.fsaseychelles.sc/"),
           "regulator": ("FSA Seychelles - licenziati", "https://www.fsaseychelles.sc/")},
    "VC": {"name": "St Vincent e Grenadine", "registry": ("FSA SVG", "https://svgfsa.com/"),
           "regulator": ("FSA SVG", "https://svgfsa.com/")},
    "VG": {"name": "British Virgin Islands", "registry": ("BVI FSC", "https://www.bvifsc.vg/"),
           "regulator": ("BVI FSC", "https://www.bvifsc.vg/")},
    "KY": {"name": "Cayman Islands", "registry": ("CIMA / General Registry", "https://www.cima.ky/"),
           "regulator": ("CIMA", "https://www.cima.ky/")},
}

# Paesi spesso citati come sede di piattaforme non autorizzate (nessun giudizio sul paese: solo promemoria)
OFFSHORE_FREQUENT = {"SC", "VC", "VG", "KY", "BZ", "MH", "WS", "VU", "LC", "KN"}

# prefissi del TLD -> paese (solo per suggerire dove guardare; non è prova di sede)
TLD_COUNTRY = {"it": "IT", "es": "ES", "pt": "PT", "fr": "FR", "de": "DE", "nl": "NL", "be": "BE", "ie": "IE",
               "uk": "GB", "ch": "CH", "at": "AT", "se": "SE", "dk": "DK", "no": "NO", "fi": "FI", "pl": "PL",
               "cz": "CZ", "gr": "GR", "us": "US", "ca": "CA", "mx": "MX", "br": "BR", "ar": "AR", "cl": "CL",
               "co": "CO", "au": "AU", "nz": "NZ", "sg": "SG", "hk": "HK", "jp": "JP", "kr": "KR", "in": "IN",
               "ae": "AE", "tr": "TR", "za": "ZA", "ng": "NG", "sc": "SC", "vg": "VG", "ky": "KY"}


def normalize_country(cc: Optional[str]) -> str:
    cc = (cc or "").strip().upper()
    return {"UK": "GB", "EL": "GR"}.get(cc, cc)


def country_from_vat(vat: Optional[str]) -> str:
    """'PT123456789' -> 'PT'. Per i numeri senza prefisso ritorna ''."""
    v = (vat or "").strip().upper().replace(" ", "")
    return normalize_country(v[:2]) if v[:2].isalpha() else ""


def country_from_domain(domain: Optional[str]) -> str:
    tld = (domain or "").rsplit(".", 1)[-1].lower()
    return TLD_COUNTRY.get(tld, "")


def verification_sources(cc: Optional[str]) -> list[tuple[str, str]]:
    """Elenco (etichetta, URL) delle fonti ufficiali da consultare per il paese `cc`, più quelle globali."""
    cc = normalize_country(cc)
    out: list[tuple[str, str]] = []
    info = COUNTRIES.get(cc)
    if info:
        out.append((f"{info['registry'][0]} ({info['name']})", info["registry"][1]))
        out.append((f"{info['regulator'][0]} ({info['name']})", info["regulator"][1]))
        out += [(f"{n} ({info['name']})", u) for n, u in info.get("also", [])]
    out += GLOBAL_SOURCES
    return out
