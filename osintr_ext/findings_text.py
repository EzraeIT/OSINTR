"""Testi (IT/EN) dei finding. Le chiavi corrispondono a Finding.code; i parametri sono in Finding.params."""
from __future__ import annotations

from .util import Finding


class _Safe(dict):
    def __missing__(self, key):
        return "n/d"


TEXT: dict[str, dict[str, tuple[str, str]]] = {
    # ------------------------------------------------------------------ on-chain
    "ONC_PASSTHROUGH_FLOW": {
        "it": ("Fondi inoltrati a un wallet collector",
               "{amount} {token} escono dal wallet destinatario e raggiungono un wallet collector in {hops} "
               "passaggio/i (circa {minutes} min complessivi). Non risultano depositati in uno smart "
               "contract di investimento."),
        "en": ("Funds forwarded to a collector wallet",
               "{amount} {token} leave the recipient wallet and reach a collector wallet in {hops} hop(s) "
               "(about {minutes} min overall). No deposit into an investment smart contract was observed."),
    },
    "ONC_COLLECTOR": {
        "it": ("Indirizzo ad alta attività (compatibile con collector)",
               "L'indirizzo {addr} su {chain} è un EOA con nonce {nonce} e saldo {balance}: profilo "
               "compatibile con raccolta/inoltro, ma da solo non prova l'attribuzione."),
        "en": ("High-activity address (collector-like)",
               "Address {addr} on {chain} is an EOA with nonce {nonce} and balance {balance}: a profile "
               "consistent with collection/forwarding, though not proof of attribution on its own."),
    },
    "ONC_STATS_PASSTHROUGH": {
        "it": ("Flussi elevati con saldo residuo minimo",
               "L'indirizzo {addr} ({chain}) ha ricevuto {received} e conserva {balance}: pattern compatibile "
               "con transito dei fondi (tipico anche di servizi legittimi: valutare il contesto)."),
        "en": ("High flows with minimal residual balance",
               "Address {addr} ({chain}) received {received} and holds {balance}: a pass-through pattern "
               "(also typical of legitimate services: assess the context)."),
    },
    "ONC_SANCTIONED": {
        "it": ("Indirizzo presente in lista sanzioni", "L'indirizzo {addr} compare in: {lists}."),
        "en": ("Address on a sanctions list", "Address {addr} appears in: {lists}."),
    },
    "ONC_BLOCKLIST": {
        "it": ("Indirizzo presente in blocklist fornita", "L'indirizzo {addr} compare in: {lists}."),
        "en": ("Address on a supplied blocklist", "Address {addr} appears in: {lists}."),
    },
    "ONC_ADDR_FROM_ENDPOINT": {
        "it": ("Indirizzi trovati in endpoint e pagine del sito",
               "{count} indirizzo/i sono stati letti automaticamente da endpoint o pagine citati dal sito stesso ({where}), "
               "senza login. Non compaiono nella pagina principale."),
        "en": ("Addresses found in site endpoints and pages",
               "{count} address(es) were read automatically from endpoints or pages the site itself references ({where}), "
               "without login. They do not appear on the main page."),
    },
    "ONC_ADDR_FOUND": {
        "it": ("Indirizzi crypto esposti dal sito",
               "Il sito espone {count} indirizzo/i crypto nel frontend ({families}), presumibilmente per "
               "raccogliere depositi."),
        "en": ("Crypto addresses exposed by the site",
               "The site exposes {count} crypto address(es) in its frontend ({families}), presumably to "
               "collect deposits."),
    },
    # ------------------------------------------------------------------ codice
    "CODE_RANDOM_UPLOADED": {
        "it": ("Operazioni 'di mercato' generate a caso nel browser e inviate al server",
               "Il JavaScript usa generatori casuali accanto a termini finanziari ({keywords}) e i valori "
               "risultano inviati al server e ripubblicati (file: {files}). Non risultano ordini firmati o "
               "ricevute di exchange."),
        "en": ("Market 'trades' generated randomly in the browser and posted to the server",
               "The JavaScript uses random generators next to financial terms ({keywords}) and the values "
               "appear to be posted to the server and re-published (files: {files}). No signed orders or "
               "exchange receipts were observed."),
    },
    "CODE_RANDOM_DATA": {
        "it": ("Valori finanziari costruiti con generatori casuali nel browser",
               "Il JavaScript usa generatori casuali vicino a termini finanziari ({keywords}) in: {files}. "
               "Euristica: può essere benigna (animazioni, demo); richiede revisione manuale."),
        "en": ("Financial values built with random generators in the browser",
               "The JavaScript uses random generators near financial terms ({keywords}) in: {files}. "
               "Heuristic: may be benign (animations, demos); needs manual review."),
    },
    "CODE_FEED_POLLING": {
        "it": ("Feed di 'operazioni recenti' aggiornato periodicamente",
               "Il frontend interroga periodicamente endpoint ({endpoints}) e ripropone i record come attività "
               "recente: se i record sono sintetici, funge da prova sociale apparente."),
        "en": ("Periodically refreshed 'recent deals' feed",
               "The frontend polls endpoints ({endpoints}) and re-displays the records as recent activity: "
               "if the records are synthetic, this works as apparent social proof."),
    },
    # ------------------------------------------------------------------ economia
    "ECO_HIGH_RETURN": {
        "it": ("Rendimenti promessi molto elevati",
               "Rendimenti trovati sul sito: {rates}. Rendimenti di questa entità sono tipicamente "
               "associati a schemi ad alto rischio o fraudolenti (HYIP/Ponzi)."),
        "en": ("Very high promised returns",
               "Returns found on the site: {rates}. Returns of this size are typically associated with "
               "high-risk or fraudulent schemes (HYIP/Ponzi)."),
    },
    "ECO_INCONSISTENT": {
        "it": ("Promesse di rendimento non coerenti tra loro",
               "Il sito riporta tassi non equivalenti ({rates}), senza metodologia verificabile."),
        "en": ("Inconsistent return promises",
               "The site states non-equivalent rates ({rates}) with no verifiable methodology."),
    },
    "ECO_GUARANTEED": {
        "it": ("Linguaggio di rendimento garantito / privo di rischio",
               "Frasi trovate: {phrases}. Nessun investimento può garantire rendimenti privi di rischio."),
        "en": ("Guaranteed / risk-free return language",
               "Phrases found: {phrases}. No investment can guarantee risk-free returns."),
    },
    "ECO_REFERRAL": {
        "it": ("Programma referral sui depositi",
               "Commissioni referral trovate: {pct}. Incentiva nuova raccolta; non dimostra alcuna attività "
               "di trading sottostante."),
        "en": ("Referral programme on deposits",
               "Referral commissions found: {pct}. It incentivises new deposits; it does not prove any "
               "underlying trading activity."),
    },
    "ECO_PRESSURE": {
        "it": ("Linguaggio di urgenza o esclusività", "Frasi trovate: {phrases}."),
        "en": ("Urgency / exclusivity language", "Phrases found: {phrases}."),
    },
    # ------------------------------------------------------------------ società
    "ENT_NO_ENTITY": {
        "it": ("Nessun soggetto giuridico dichiarato",
               "Nel sito non è stato individuato un soggetto giuridico identificabile (ragione sociale, "
               "numero di registro o partita IVA)."),
        "en": ("No legal entity declared",
               "No identifiable legal entity (company name, registry or VAT number) was found on the site."),
    },
    "ENT_VAT_OK": {
        "it": ("Partita IVA valida in VIES", "VIES conferma {vat}: {name}."),
        "en": ("VAT number valid in VIES", "VIES confirms {vat}: {name}."),
    },
    "ENT_VAT_INVALID": {
        "it": ("Partita IVA non valida in VIES", "VIES indica che {vat} non è valida."),
        "en": ("VAT number invalid in VIES", "VIES reports that {vat} is not valid."),
    },
    "ENT_NAME_MISMATCH": {
        "it": ("Denominazione non corrispondente al registro",
               "La denominazione dichiarata ('{declared}') differisce da quella registrata ('{registered}')."),
        "en": ("Company name differs from the registry",
               "The declared name ('{declared}') differs from the registered one ('{registered}')."),
    },
    "ENT_LEI_NOT_FOUND": {
        "it": ("Nessun record LEI", "Nessun record GLEIF per '{name}': non significativo di per sé."),
        "en": ("No LEI record", "No GLEIF record for '{name}': not meaningful on its own."),
    },
    "ENT_SANCTION_MATCH": {
        "it": ("Possibile corrispondenza in liste sanzioni/PEP",
               "OpenSanctions ha restituito {count} possibili corrispondenze per '{name}' (punteggio massimo "
               "{score}). Da verificare manualmente: i falsi positivi sono frequenti."),
        "en": ("Possible sanctions/PEP match",
               "OpenSanctions returned {count} possible match(es) for '{name}' (top score {score}). Verify "
               "manually: false positives are common."),
    },
    "ENT_RECENT_INCORP": {
        "it": ("Società costituita di recente",
               "Costituita il {date}, {days} giorni prima dell'analisi."),
        "en": ("Recently incorporated company", "Incorporated on {date}, {days} days before the analysis."),
    },
    "ENT_DOMAIN_BEFORE_INCORP": {
        "it": ("Dominio registrato prima della costituzione della società",
               "Il dominio ({domain_date}) precede la costituzione della società ({inc_date})."),
        "en": ("Domain registered before the company existed",
               "The domain ({domain_date}) predates the company's incorporation ({inc_date})."),
    },
    "ENT_CNPJ_INACTIVE": {
        "it": ("CNPJ non attivo",
               "Il CNPJ risulta con situazione cadastrale '{status}' per {name} nel registro pubblico brasiliano."),
        "en": ("CNPJ not active",
               "The CNPJ shows registration status '{status}' for {name} in the Brazilian public registry."),
    },
    "ENT_CNPJ_NOT_FOUND": {
        "it": ("CNPJ non trovato",
               "Il CNPJ {cnpj} non è stato trovato nella fonte pubblica interrogata (può essere un limite della fonte)."),
        "en": ("CNPJ not found",
               "CNPJ {cnpj} was not found in the public source queried (this may be a limit of the source)."),
    },
    "ENT_OFFSHORE_JURISDICTION": {
        "it": ("Giurisdizione frequente per piattaforme non autorizzate",
               "L'entità fa capo a una giurisdizione ({country}) spesso usata da piattaforme non autorizzate. "
               "Non è prova di illecito: va verificata la licenza presso l'autorità locale."),
        "en": ("Jurisdiction often used by unauthorised platforms",
               "The entity is linked to a jurisdiction ({country}) often used by unauthorised platforms. "
               "It is not proof of wrongdoing: verify the licence with the local authority."),
    },
    # ------------------------------------------------------------------ dati dello script osint_recon.py
    "INF_NO_WAYBACK": {
        "it": ("Nessuno storico su Wayback Machine",
               "Il dominio non ha snapshot su Archive.org. È coerente con un sito recente o mai indicizzato; da solo non è una prova."),
        "en": ("No Wayback Machine history",
               "The domain has no snapshots on Archive.org. This fits a recent or never-indexed site; on its own it proves nothing."),
    },
    "INF_SUBDOMAINS": {
        "it": ("Sottodomini nei log di Certificate Transparency",
               "Nei log CT risultano {count} nomi di host associati al dominio (elenco nella sezione dedicata)."),
        "en": ("Subdomains in Certificate Transparency logs",
               "CT logs list {count} host names associated with the domain (see the dedicated section)."),
    },
    "INF_TYPO_REGISTERED": {
        "it": ("Varianti del dominio già registrate",
               "{count} varianti su {checked} verificate risultano registrate e risolvono (es. {examples}). Può indicare una rete "
               "di domini gemelli oppure semplici coincidenze: va verificato."),
        "en": ("Lookalike domains already registered",
               "{count} of {checked} variants checked are registered and resolve (e.g. {examples}). This may indicate a twin "
               "domain network or mere coincidence: verify."),
    },
    "INF_TYPO_SAME_IP": {
        "it": ("Varianti del dominio sullo stesso IP",
               "Alcune varianti registrate risolvono sullo stesso IP del sito ({examples}): segnale più forte di una gestione comune."),
        "en": ("Lookalike domains on the same IP",
               "Some registered variants resolve to the same IP as the site ({examples}): a stronger sign of common management."),
    },
    "INF_RELATED_DOMAINS": {
        "it": ("Pochi domini sullo stesso IP",
               "Solo {count} domini condividono l'IP (es. {examples}). Con numeri così bassi può essere un collegamento reale, "
               "ma va incrociato con registrant e nameserver."),
        "en": ("Few domains on the same IP",
               "Only {count} domains share the IP (e.g. {examples}). With numbers this low it may be a real link, "
               "but cross-check registrant and nameservers."),
    },
    "INF_ABUSE_IP": {
        "it": ("IP segnalato per abusi",
               "L'IP del sito ha un punteggio AbuseIPDB di {score} con {reports} segnalazioni negli ultimi 90 giorni."),
        "en": ("IP reported for abuse",
               "The site's IP has an AbuseIPDB score of {score} with {reports} reports in the last 90 days."),
    },
    "INF_EXPOSED_PORTS": {
        "it": ("Servizi sensibili noti a Shodan sull'IP",
               "Shodan InternetDB riporta porte tipicamente non pubbliche: {ports}. Dato passivo, non verificato da noi."),
        "en": ("Sensitive services known to Shodan on the IP",
               "Shodan InternetDB lists ports that are normally not public: {ports}. Passive data, not verified by us."),
    },
    "INF_KNOWN_CVES": {
        "it": ("Software con vulnerabilità note (non confermate)",
               "Per il software rilevato ({software}) NVD elenca {count} CVE. Non conferma che il sito sia vulnerabile."),
        "en": ("Software with known vulnerabilities (unconfirmed)",
               "For the detected software ({software}) NVD lists {count} CVEs. This does not confirm the site is vulnerable."),
    },
    "INF_BREACHED_EMAIL": {
        "it": ("Email di contatto presenti in violazioni di dati",
               "{count} delle {total} email trovate nel sito compaiono in violazioni note. Dato di contesto, non indizio di frode."),
        "en": ("Contact emails found in data breaches",
               "{count} of the {total} emails found on the site appear in known breaches. Context only, not a fraud indicator."),
    },
    "INF_DARKWEB_HITS": {
        "it": ("Riferimenti in fonti di leak o dark web",
               "IntelligenceX riporta {count} risultati collegati al dominio (copertura parziale)."),
        "en": ("References in leak or dark web sources",
               "IntelligenceX reports {count} results linked to the domain (partial coverage)."),
    },
    "INF_SANCTIONS_NAME": {
        "it": ("Possibile corrispondenza nelle liste di sanzioni",
               "Il nome {name} ha {count} corrispondenze nella Consolidated Screening List ({sources}). Una corrispondenza per nome "
               "può essere un falso positivo: verificare i dettagli prima di trarre conclusioni."),
        "en": ("Possible match in sanctions lists",
               "The name {name} has {count} matches in the Consolidated Screening List ({sources}). A name match may be a "
               "false positive: check the details before drawing conclusions."),
    },
    "DOM_YOUNG": {
        "it": ("Dominio molto recente",
               "Dominio registrato il {date}, {days} giorni prima dell'analisi. Red flag contestuale, non "
               "prova autonoma."),
        "en": ("Very recent domain",
               "Domain registered on {date}, {days} days before the analysis. Contextual red flag, not "
               "stand-alone proof."),
    },
    "DOM_RDAP_UNAVAILABLE": {
        "it": ("Dati RDAP non disponibili", "Nessuna risposta RDAP per {domain}."),
        "en": ("RDAP data unavailable", "No RDAP response for {domain}."),
    },
    # ------------------------------------------------------------------ web
    "WEB_LEGAL_MISSING": {
        "it": ("Documenti legali non individuati",
               "Nel sito non sono stati trovati link a termini, privacy o informazioni legali."),
        "en": ("Legal documents not found",
               "No links to terms, privacy or legal information were found on the site."),
    },
    "WEB_LEGAL_THIN": {
        "it": ("Documenti legali materialmente insufficienti",
               "Pagine legali vuote o molto brevi: {pages}. Mancano regole su custodia, rimborsi, rischi, "
               "titolare e trattamento dati."),
        "en": ("Legal documents materially insufficient",
               "Empty or very short legal pages: {pages}. Rules on custody, refunds, risks, controller and "
               "data processing are missing."),
    },
    "WEB_OLD_SERVER": {
        "it": ("Tecnologia server obsoleta",
               "Header osservato: {server}. Versione fuori supporto: aumenta il rischio di vulnerabilità."),
        "en": ("Outdated server technology",
               "Observed header: {server}. Unsupported version: increases vulnerability risk."),
    },
    "WEB_HEADERS_MISSING": {
        "it": ("Security header assenti o incompleti", "Header assenti: {missing}."),
        "en": ("Missing or incomplete security headers", "Missing headers: {missing}."),
    },
    "WEB_CORS": {
        "it": ("CORS permissivo osservato",
               "Access-Control-Allow-Origin: {acao}; Allow-Credentials: {acac}. Osservazione passiva, non "
               "testata attivamente."),
        "en": ("Permissive CORS observed",
               "Access-Control-Allow-Origin: {acao}; Allow-Credentials: {acac}. Passive observation, not "
               "actively tested."),
    },
    "WEB_COOKIES": {
        "it": ("Cookie senza tutti gli attributi di sicurezza", "Cookie: {cookies}."),
        "en": ("Cookies without all security attributes", "Cookies: {cookies}."),
    },
}


def render_finding(f: Finding, lang: str = "it") -> tuple[str, str]:
    """Ritorna (titolo, dettaglio) nella lingua richiesta."""
    if f.code == "MANUAL" or f.code not in TEXT:
        return f.title or f.code, f.detail
    title, detail = TEXT[f.code].get(lang, TEXT[f.code]["it"])
    text = detail.format_map(_Safe(f.params))
    if lang == "it" and f.code.startswith("ECO_"):
        for en, it in ((" daily", " al giorno"), (" weekly", " a settimana"), (" monthly", " al mese"),
                       (" yearly", " all'anno"), ("/yr", "/anno")):
            text = text.replace(en, it)
    return title, text
