"""Generatore del rapporto tecnico-forense preliminare in PDF (IT/EN).

Struttura ispirata ai rapporti forensi su schemi di investimento crypto: esito sintetico, sintesi esecutiva,
metodo e integrità delle prove (SHA-256), ricostruzione on-chain con diagramma, stato dei wallet, analisi del
codice client, incongruenze economiche, società/dominio, superficie web, matrice di rischio, azioni, appendici.

Ogni conclusione è classificata come fatto, interpretazione o limite. Il rapporto NON è un parere legale né una
perizia giudiziaria; le euristiche automatiche vanno riviste da un analista.
"""
from __future__ import annotations

from datetime import date
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (BaseDocTemplate, Flowable, Frame, KeepTogether, PageBreak, PageTemplate,
                                Paragraph, Spacer, Table, TableStyle)

from .case import all_findings
from .findings_text import render_finding
from . import registries
from .util import SEV_ORDER, VERSION, assess, short

NAVY = colors.HexColor("#0f172a")
BLUE = colors.HexColor("#2563eb")
GREY = colors.HexColor("#64748b")
LIGHT = colors.HexColor("#f1f5f9")
HEAD = colors.HexColor("#e2e8f0")
LINE = colors.HexColor("#cbd5e1")
SEV_COLOR = {"critical": "#b91c1c", "high": "#ea580c", "medium": "#a16207", "low": "#2563eb", "info": "#64748b"}
LEVEL_COLOR = {"critical": "#b91c1c", "high": "#c2410c", "medium": "#a16207", "low": "#15803d"}
W = 170 * mm

MONTHS = {
    "it": ["gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno", "luglio", "agosto", "settembre",
           "ottobre", "novembre", "dicembre"],
    "en": ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
           "November", "December"],
}

S = {
    "it": {
        "title": "RAPPORTO TECNICO-FORENSE PRELIMINARE",
        "subtitle": "Valutazione di {target} e dei dati pubblici e on-chain collegati",
        "outcome": "ESITO SINTETICO",
        "levels": {"critical": "RISCHIO CRITICO", "high": "RISCHIO ALTO", "medium": "RISCHIO MEDIO",
                   "low": "RISCHIO BASSO"},
        "conclusion": {
            "critical": "Conclusione tecnica: probabilità molto alta che il servizio presenti caratteristiche "
                        "ingannevoli e/o fraudolente. Non è una sentenza né un'attribuzione penale.",
            "high": "Conclusione tecnica: probabilità alta di caratteristiche ingannevoli o di rischio rilevante. "
                    "Non è una sentenza né un'attribuzione penale.",
            "medium": "Conclusione tecnica: emergono segnali di rischio che richiedono verifiche ulteriori prima "
                      "di qualsiasi versamento. Non è una sentenza né un'attribuzione penale.",
            "low": "Conclusione tecnica: nei controlli automatici eseguiti non emergono segnali forti, ma "
                   "l'assenza di evidenze non equivale a legittimità.",
        },
        "version": "Versione {v} | {d} | {tz}",
        "ref": "Rif. pratica: {r}",
        "analyst": "Analista: {a}",
        "conf_doc": "Documento riservato - copia privacy-safe",
        "conf_doc_full": "Documento riservato - contiene identificativi completi",
        "hdr": "{t} - RAPPORTO TECNICO-FORENSE PRELIMINARE",
        "hdr_r": "RISERVATO",
        "ftr": "Analisi del {d}",
        "ftr_priv": " - Identificativi personali abbreviati",
        "page": "Pagina {n}",
        "s_exec": "Sintesi esecutiva",
        "verdict": "Verdetto tecnico",
        "plain_title": "In parole semplici",
    "plain_opening": {
        "critical": "Questo sito presenta segnali molto forti e multipli di una possibile truffa. Il consiglio "
                    "tecnico è di non inviare altro denaro e di agire subito (vedi sezione 9).",
        "high": "Questo sito presenta diversi segnali seri che, messi insieme, indicano un rischio concreto. "
               "Prima di inviare altro denaro servono verifiche indipendenti.",
        "medium": "Questo sito presenta alcuni segnali che da soli non bastano a dire che è una truffa, ma "
                  "che meritano verifiche prima di fidarsi o di inviare altro denaro.",
        "low": "In questa analisi non sono emersi segnali forti di frode. Restano comunque alcuni punti da "
              "verificare, elencati sotto, prima di considerare il sito affidabile.",
    },
    "plain_points_intro": "Nel dettaglio, ecco cosa pesa di più in questo giudizio:",
    "plain_none": "Nessun segnale specifico degno di nota oltre a quanto già scritto sopra.",
    "plain_closing": "Questa sintesi semplifica un'analisi tecnica più estesa (sezioni successive): per i dettagli, "
                     "le fonti e i limiti di ogni singolo controllo, continua a leggere il rapporto.",
    "verdict_txt": "Le evidenze convergono verso un livello di {lvl} (punteggio {score}). "
                       "Elementi principali: {items}.",
        "why": "Perché il giudizio è forte",
        "why_cols": ["Evidenza", "Osservazione verificata", "Peso"],
        "weights": {"critical": "Molto alto", "high": "Alto", "medium": "Medio", "low": "Basso", "info": "Info"},
        "proves": "Cosa dimostra l'evidenza fornita",
        "proves_txt": "Dimostra che il wallet/exchange di origine ha completato un trasferimento verso un "
                      "indirizzo esterno. <b>Non dimostra</b> che il destinatario sia un investimento autorizzato, "
                      "che il denaro sia stato effettivamente impiegato in operazioni di trading o che il saldo "
                      "mostrato dal sito sia riscattabile.",
        "s_method": "Perimetro, metodo e trattamento delle prove",
        "method_txt": "Il lavoro combina analisi statica del frontend pubblico, verifiche sul ledger tramite "
                      "RPC/API pubbliche e consultazione di fonti pubbliche societarie e di dominio. Ogni "
                      "conclusione è classificata come <b>fatto</b>, <b>interpretazione</b> o <b>limite</b>. "
                      "Le euristiche automatiche possono produrre falsi positivi e vanno riviste da un analista.",
        "sources": "Fonti acquisite",
        "privacy": "Privacy e integrità",
        "priv_cols": ["Elemento", "Trattamento nel PDF"],
        "priv_rows": [["Indirizzi e hash di transazione", "Abbreviati nel testo (allegato riservato separato)"],
                      ["Importo e rete", "Mantenuti: essenziali per interpretare il caso"],
                      ["File originali", "Non incorporati; impronta SHA-256 riportata sotto"]],
        "hash_cols": ["File", "SHA-256"],
        "hash_note": "L'impronta consente di dimostrare che il file non è stato alterato dopo l'acquisizione. "
                     "Conservare gli originali separatamente e non pubblicarli.",
        "s_tx": "Evidenza fornita: transazione",
        "tx_cols": ["Campo", "Valore"],
        "tx_fields": ["Rete", "Token", "Importo", "Da", "A", "Blocco", "Stato", "Hash"],
        "s_chain": "Ricostruzione on-chain",
        "chain_txt": "Le blockchain pubbliche registrano le chiamate ai contratti token e gli eventi Transfer. "
                     "Gli identificativi completi sono riportati solo nell'allegato riservato.",
        "phase_cols": ["Fase", "Evidenza tecnica", "Esito"],
        "confirmed": "Confermato",
        "not_traced": "Tracciamento in avanti non eseguito (serve una API key di un explorer): il flusso "
                      "mostra solo il primo passaggio osservato.",
        "chain_concl": "Conclusione del tracciamento",
        "chain_concl_txt": "Il flusso è compatibile con un sistema di raccolta e inoltro. Non è stata osservata "
                           "una posizione on-chain riconducibile a staking, arbitraggio o investimento del capitale. "
                           "Il saldo mostrato dal sito può essere un valore di database interno.",
        "proven_cols": ["Livello", "Affermazione"],
        "proven_rows": [["Fatto", "I fondi hanno seguito la sequenza descritta; gli importi dei passaggi coincidono."],
                        ["Interpretazione forte", "La dinamica è tipica di una pipeline di raccolta/inoltro e non "
                                                  "di un conto di investimento segregato."],
                        ["Non dimostrato", "L'identità reale dei titolari dei wallet e il beneficiario economico finale."]],
        "s_wallets": "Stato tecnico dei wallet e degli indirizzi",
        "wallet_cols": ["Nodo", "Indirizzo", "Tipo", "Attività", "Saldo", "Lettura"],
        "poison": "Rischio address-poisoning",
        "poison_txt": "Non copiare mai un indirizzo dalla cronologia recente: recuperarlo dalla fonte originaria, "
                      "verificare inizio e fine e, per importi rilevanti, eseguire prima una micro-transazione.",
        "s_code": "Analisi del codice client",
        "code_cols": ["File", "Termini finanziari vicini a generatori casuali", "Estratto"],
        "code_none": "Nessun indicatore di dati generati casualmente trovato nell'analisi statica (limite: il "
                     "codice caricato dinamicamente o offuscato può sfuggire).",
        "feed": "Endpoint interrogati periodicamente",
        "s_eco": "Incongruenze economiche e di prodotto",
        "eco_cols": ["Estratto dal sito", "Tasso", "Periodo", "Annualizzato (semplice)"],
        "eco_none": "Nessuna promessa di rendimento con periodo esplicito individuata.",
        "periods": {"daily": "giornaliero", "weekly": "settimanale", "monthly": "mensile", "yearly": "annuo"},
        "behav": "Indicatore comportamentale",
        "behav_txt": "Se viene richiesto un ulteriore versamento per sbloccare prelievi, pagare tasse, commissioni, "
                     "gas, verifica AML o upgrade del piano, non pagare: è uno schema ricorrente di "
                     "advance-fee fraud.",
        "s_ent": "Società, dominio e quadro regolamentare",
        "ent_cols": ["Controllo", "Esito", "Limite"],
        "dom_reg": "Dominio registrato",
        "dom_age": "Età del dominio",
        "dom_registrar": "Registrar",
        "dom_ns": "Nameserver",
        "dom_lim": "Un dominio giovane è un red flag contestuale, non una prova autonoma.",
        "days": "{n} giorni",
        "declared": "Soggetto dichiarato nel sito",
        "none_found": "Nessuno individuato",
        "vies": "VIES (partita IVA UE)",
        "gleif": "GLEIF (LEI)",
        "valid": "valida", "invalid": "non valida", "norecord": "nessun record", "unavail": "non disponibile",
        "ent_lim": "L'assenza di un record non prova nulla; l'assenza di warning non equivale ad autorizzazione.",
        "manual_checks": "Da verificare manualmente",
        "manual_rows": [
            ["Visura/certificato ufficiale del registro imprese competente",
             "Acquisire il documento ufficiale aggiornato (le schede di aggregatori non bastano per uso giudiziario)."],
            ["Oggetto sociale e attività autorizzate vs modello commerciale del sito",
             "Confrontare l'oggetto pubblicato con ciò che il sito promette."],
            ["Autorizzazione/registrazione come fornitore di servizi per cripto-attività",
             "Registro ESMA MiCA e autorità nazionale di vigilanza; per l'extra-UE il regolatore locale."],
            ["Avvisi alle autorità di vigilanza", "Elenchi di warning nazionali e IOSCO I-SCAN."],
        ],
        "to_verify": "Da verificare",
        "s_web": "Superficie web e controlli di sicurezza",
        "web_cols": ["Elemento", "Osservazione"],
        "web_note": "Fotografia passiva del servizio, non un penetration test. Non sono state tentate "
                    "autenticazioni, bypass, injection o azioni distruttive. TLS protegge il trasporto, non "
                    "certifica l'affidabilità economica.",
        "present": "presente", "absent": "assente",
        "legal_pages": "Pagine legali",
        "legal_none": "Nessuna pagina legale raggiungibile",
        "chars": "caratteri",
        "creds": "Credenziali",
        "creds_txt": "Se la password usata sul sito è stata riutilizzata altrove, cambiarla subito ovunque e "
                     "attivare l'autenticazione a più fattori. Non inviare documenti aggiuntivi al sito.",
        "s_risk": "Matrice di rischio",
        "risk_cols": ["Indicatore", "Gravità", "Confidenza", "Natura", "Base"],
        "sev": {"critical": "Critica", "high": "Alta", "medium": "Media", "low": "Bassa", "info": "Info"},
        "conf": {"high": "Alta", "medium-high": "Medio-alta", "medium": "Media", "low": "Bassa"},
        "kind": {"fact": "Fatto", "interpretation": "Interpretazione", "limit": "Limite"},
        "overall": "VALUTAZIONE COMPLESSIVA",
        "overall_txt": "La valutazione non deriva da un singolo indizio ma dalla convergenza di elementi "
                       "indipendenti. Punteggio euristico: {score}. La decisione finale spetta all'analista.",
        "s_act": "Azioni raccomandate",
        "act_cols": ["Priorità", "Azione", "Obiettivo"],
        "act_rows_always": [
            ["P0", "Non inviare altri fondi, neppure per commissioni, tasse, AML, gas o sblocco.",
             "Impedire ulteriori perdite."],
            ["P0", "Conservare chat, username, email, URL, ricevute, schermate del saldo e richieste di pagamento.",
             "Creare una catena probatoria."],
            ["P0", "Cambiare eventuali password riutilizzate e abilitare MFA.", "Ridurre il rischio di account takeover."],
        ],
        "act_tx": ["P0", "Aprire subito un caso scam/fraud con l'exchange o il wallet provider di origine; allegare "
                         "TxID completo e questo rapporto.",
                   "Preservare tempi, log e possibile cooperazione con exchange/autorità."],
        "act_police": ["P1", "Presentare segnalazione/denuncia alle forze dell'ordine competenti ({p}), con gli "
                             "identificativi completi in allegato riservato.",
                       "Attivare gli strumenti investigativi formali."],
        "act_reg": ["P1", "Segnalare il soggetto all'autorità di vigilanza finanziaria ({r}).",
                    "Far verificare eventuale abusivismo."],
        "recovery": "Recupero fondi",
        "recovery_txt": "Le transazioni blockchain confermate non sono reversibili unilateralmente. Un recupero "
                        "può dipendere dall'identificazione del beneficiario, dal congelamento presso un soggetto "
                        "custodial o da un provvedimento dell'autorità. Diffidare dei recovery agent che chiedono "
                        "anticipi o promettono recuperi certi.",
        "pack": "Pacchetto probatorio minimo",
        "pack_items": ["File originali non redatti e relativo SHA-256.",
                       "Export della cronologia dell'exchange e ricevuta del prelievo.",
                       "TxID e indirizzi completi in un documento separato riservato.",
                       "Chat integrali con timestamp, non solo screenshot selettivi.",
                       "URL del sito, username dell'account, condizioni mostrate e richieste di pagamento.",
                       "Timeline scritta dei contatti, redatta mentre i ricordi sono freschi."],
        "app_a": "Appendice A - Dettagli tecnici riproducibili",
        "app_a_txt": "Per ragioni di privacy gli identificativi sono abbreviati in questa copia; la copia destinata "
                     "alle autorità deve integrare un allegato con i valori completi.",
        "app_a_rpc": "Chiamate JSON-RPC usate: eth_getCode, eth_getTransactionCount, eth_getBalance, "
                     "eth_getTransactionReceipt, eth_getBlockByNumber, eth_blockNumber, eth_call balanceOf(address).",
        "sel_cols": ["Selector", "Funzione", "Uso"],
        "sel_rows": [["0xa9059cbb", "transfer(address,uint256)", "Trasferimenti di token ERC-20"],
                     ["0x095ea7b3", "approve(address,uint256)", "Allowance a uno spender"],
                     ["0x70a08231", "balanceOf(address)", "Saldo token di un indirizzo"]],
        "repeat": "Controlli di ripetibilità: verificare receipt status = 1, decodificare target e uint256 dall'input, "
                  "confrontare l'evento Transfer nei log, controllare eth_getCode = 0x per distinguere EOA da "
                  "contratto; annotare blocco, timestamp UTC ed endpoint RPC.",
        "app_b": "Appendice B - Riferimenti",
        "refs": ["EIP-20 - Token Standard", "RDAP (RFC 7480 e successivi) - data di registrazione del dominio",
                 "VIES - validazione partite IVA UE (ec.europa.eu/taxation_customs/vies)",
                 "GLEIF - Legal Entity Identifier (gleif.org)",
                 "OFAC SDN - indirizzi crypto sanzionati (treasury.gov/ofac)",
                 "ESMA - registri MiCA (esma.europa.eu)", "IOSCO I-SCAN - warning dei regolatori (iosco.org/i-scan)"],
        "limits": "Limitazioni",
        "limits_items": ["Analisi tecnica preliminare: non è un parere legale né una perizia giudiziaria.",
                         "Nessuna attribuzione certa della titolarità dei wallet.",
                         "Nessun accesso a contabilità, backend, database, ordini di exchange o chiavi private.",
                         "L'assenza di un warning specifico non certifica l'operatore.",
                         "Saldi e nonce on-chain sono dinamici e rappresentano lo snapshot indicato.",
                         "Le euristiche automatiche (JavaScript, testi, pattern di flusso) possono dare falsi "
                         "positivi e vanno rivedute da un analista.",
                         "Per uso giudiziario acquisire visure e certificati ufficiali aggiornati."],
        "final": "Conclusione finale",
        "final_txt": {
            "critical": "Sulla base delle prove disponibili, continuare a versare denaro o affidare dati al servizio "
                        "non è ragionevole. La priorità è interrompere i pagamenti, preservare le prove e "
                        "attivare exchange e autorità competenti.",
            "high": "Sulla base delle prove disponibili, il livello di rischio è alto: evitare nuovi versamenti, "
                    "preservare le prove e approfondire con le autorità e un legale.",
            "medium": "Sono emersi segnali di rischio: sospendere i versamenti fino a verifiche indipendenti "
                      "sull'identità e sulle autorizzazioni dell'operatore.",
            "low": "I controlli eseguiti non mostrano segnali forti, ma restano necessarie le verifiche manuali "
                   "indicate prima di qualsiasi decisione.",
        },
        "police": {"IT": "Polizia Postale", "ES": "Policía Nacional / Guardia Civil", "PT": "Polícia Judiciária",
                   "GB": "polizia locale / servizio nazionale di segnalazione frodi", "US": "FBI IC3",
                   "DE": "polizia locale (Landeskriminalamt)", "FR": "polizia/gendarmerie e piattaforma Pharos",
                   "BR": "Polícia Federal / Polícia Civil", "": "unità di cybercrime della polizia del tuo paese"},
        "regulator": {"IT": "Consob", "ES": "CNMV", "PT": "CMVM / Banco de Portugal", "GB": "FCA", "US": "SEC / CFTC / FTC",
                      "DE": "BaFin", "FR": "AMF", "BR": "CVM / Banco Central do Brasil",
                      "": "autorità di vigilanza dei mercati finanziari del tuo paese"},
        "yes": "sì", "no": "no", "na": "n/d",
    },
}

S["it"].update({
    "ep_title": "Endpoint e pagine consultati (solo GET, senza login)",
    "ep_cols": ["URL", "Esito", "Indirizzi", "Campi/categorie riconosciuti"],
    "ep_note": "Richieste limitate ai percorsi citati dal sito, stesso host, senza cookie. Gli endpoint che richiedono il login sono registrati (stato/testo) e non vengono letti oltre. Campi e categorie sono indicatori: non provano da soli che l'endpoint contenga dati finanziari reali o utilizzabili.",
    "s_extra": "Infrastruttura, cronologia e reti collegate",
    "ver_sources": "Fonti ufficiali da consultare per la verifica formale",
    "ver_cols": ["Fonte", "Collegamento"],
    "cnpj": "CNPJ (Receita Federal, via BrasilAPI)",
    "country_hint": "Paese di riferimento per le verifiche: {c}",
    "country_inferred": "Paese NON dichiarato esplicitamente: dedotto da un indizio debole del sito ({src}). Da confermare manualmente.",
    "geo_title": "Verifica geografica dell'indirizzo dichiarato",
    "geo_cols": ["Campo", "Valore"],
    "geo_addr": "Indirizzo dichiarato",
    "geo_resolved": "Risolto come",
    "geo_country": "Paese rilevato",
    "geo_precision": "Precisione",
    "geo_precise": "a livello di edificio/via",
    "geo_vague": "generica (area/città, non l'edificio specifico)",
    "geo_note": "Fonte: Nominatim (OpenStreetMap). Verifica di plausibilità su un indirizzo già dichiarato "
                "pubblicamente in un registro societario, non localizzazione di una persona. Un indirizzo non "
                "trovato o generico non è prova di frode: può dipendere da una domiciliazione legittima o da un "
                "errore di trascrizione.",
})

S["en"] = {
    **S["it"],
    "ep_title": "Endpoints and pages consulted (GET only, no login)",
    "ep_cols": ["URL", "Result", "Addresses", "Recognized fields/categories"],
    "ep_note": "Requests limited to paths the site itself references, same host, no cookies. Endpoints requiring login are logged (status/text) and not read further. Fields and categories are indicators: they do not by themselves prove the endpoint holds real or usable financial data.",
    "s_extra": "Infrastructure, history and related networks",
    "ver_sources": "Official sources to consult for formal verification",
    "ver_cols": ["Source", "Link"],
    "cnpj": "CNPJ (Receita Federal, via BrasilAPI)",
    "country_hint": "Reference country for the checks: {c}",
    "country_inferred": "Country NOT explicitly declared: inferred from a weak site hint ({src}). To be confirmed manually.",
    "geo_title": "Geographic verification of the declared address",
    "geo_cols": ["Field", "Value"],
    "geo_addr": "Declared address",
    "geo_resolved": "Resolved as",
    "geo_country": "Detected country",
    "geo_precision": "Precision",
    "geo_precise": "building/street level",
    "geo_vague": "generic (area/city, not the specific building)",
    "geo_note": "Source: Nominatim (OpenStreetMap). A plausibility check on an address already declared publicly "
                "in a company registry, not the location of a person. A not-found or generic address is not proof "
                "of fraud: it may reflect a legitimate registered-office arrangement or a transcription error.",
    "title": "PRELIMINARY TECHNICAL-FORENSIC REPORT",
    "subtitle": "Assessment of {target} and the related public and on-chain data",
    "outcome": "SUMMARY OUTCOME",
    "levels": {"critical": "CRITICAL RISK", "high": "HIGH RISK", "medium": "MEDIUM RISK", "low": "LOW RISK"},
    "conclusion": {
        "critical": "Technical conclusion: very high probability that the service shows deceptive and/or fraudulent "
                    "characteristics. This is not a judgment nor a criminal attribution.",
        "high": "Technical conclusion: high probability of deceptive characteristics or significant risk. This is "
                "not a judgment nor a criminal attribution.",
        "medium": "Technical conclusion: risk signals emerge that require further checks before any payment. This "
                  "is not a judgment nor a criminal attribution.",
        "low": "Technical conclusion: the automated checks show no strong signals, but absence of evidence is not "
               "proof of legitimacy.",
    },
    "version": "Version {v} | {d} | {tz}",
    "ref": "Case ref: {r}",
    "analyst": "Analyst: {a}",
    "conf_doc": "Confidential document - privacy-safe copy",
    "conf_doc_full": "Confidential document - contains full identifiers",
    "hdr": "{t} - PRELIMINARY TECHNICAL-FORENSIC REPORT",
    "hdr_r": "CONFIDENTIAL",
    "ftr": "Analysis of {d}",
    "ftr_priv": " - Personal identifiers abbreviated",
    "page": "Page {n}",
    "s_exec": "Executive summary",
    "verdict": "Technical verdict",
    "plain_title": "In plain language",
    "plain_opening": {
        "critical": "This site shows very strong, multiple signs of a possible scam. The technical advice is to "
                    "stop sending money and act now (see section 9).",
        "high": "This site shows several serious signs that, together, point to a real risk. Independent checks "
               "are needed before sending any more money.",
        "medium": "This site shows some signs that are not enough on their own to call it a scam, but that "
                  "deserve checking before trusting it or sending more money.",
        "low": "This analysis did not find strong signs of fraud. A few points still need checking, listed "
              "below, before considering the site trustworthy.",
    },
    "plain_points_intro": "In detail, here is what weighs most in this assessment:",
    "plain_none": "No specific signal beyond what is already written above.",
    "plain_closing": "This summary simplifies a longer technical analysis (sections below): for details, "
                     "sources and the limits of each check, keep reading the report.",
    "verdict_txt": "The evidence converges on a {lvl} level (score {score}). Main elements: {items}.",
    "why": "Why the assessment is strong",
    "why_cols": ["Evidence", "Verified observation", "Weight"],
    "weights": {"critical": "Very high", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"},
    "proves": "What the supplied evidence shows",
    "proves_txt": "It shows that the originating wallet/exchange completed a transfer to an external address. It "
                  "<b>does not show</b> that the recipient is an authorised investment, that the money was actually "
                  "traded, or that the balance displayed by the site can be withdrawn.",
    "s_method": "Scope, method and evidence handling",
    "method_txt": "The work combines static analysis of the public frontend, ledger checks via public RPC/APIs and "
                  "public corporate and domain sources. Every conclusion is classified as <b>fact</b>, "
                  "<b>interpretation</b> or <b>limit</b>. Automated heuristics can produce false positives and must "
                  "be reviewed by an analyst.",
    "sources": "Sources acquired",
    "privacy": "Privacy and integrity",
    "priv_cols": ["Item", "Treatment in this PDF"],
    "priv_rows": [["Addresses and transaction hashes", "Abbreviated in the text (separate confidential annex)"],
                  ["Amount and network", "Kept: essential to interpret the case"],
                  ["Original files", "Not embedded; SHA-256 fingerprint listed below"]],
    "hash_cols": ["File", "SHA-256"],
    "hash_note": "The fingerprint makes it possible to show the file was not altered after acquisition. Keep the "
                 "originals separately and do not publish them.",
    "s_tx": "Evidence supplied: transaction",
    "tx_cols": ["Field", "Value"],
    "tx_fields": ["Network", "Token", "Amount", "From", "To", "Block", "Status", "Hash"],
    "s_chain": "On-chain reconstruction",
    "chain_txt": "Public blockchains record token-contract calls and Transfer events. Full identifiers appear only "
                 "in the confidential annex.",
    "phase_cols": ["Step", "Technical evidence", "Result"],
    "confirmed": "Confirmed",
    "not_traced": "Forward tracing was not run (an explorer API key is required): the flow shows only the first "
                  "observed hop.",
    "chain_concl": "Tracing conclusion",
    "chain_concl_txt": "The flow is consistent with a collect-and-forward system. No on-chain position attributable "
                       "to staking, arbitrage or investment of the capital was observed. The balance shown by the "
                       "site may be an internal database value.",
    "proven_cols": ["Level", "Statement"],
    "proven_rows": [["Fact", "The funds followed the described sequence; the amounts of the hops match."],
                    ["Strong interpretation", "The dynamics are typical of a collection/forwarding pipeline, not of "
                                              "a segregated investment account."],
                    ["Not proven", "The real-world identity of the wallet owners and the final economic beneficiary."]],
    "s_wallets": "Technical status of wallets and addresses",
    "wallet_cols": ["Node", "Address", "Type", "Activity", "Balance", "Reading"],
    "poison": "Address-poisoning risk",
    "poison_txt": "Never copy an address from recent history: retrieve it from the original source, check the "
                  "beginning and end and, for large amounts, send a micro-transaction first.",
    "s_code": "Client-side code analysis",
    "code_cols": ["File", "Financial terms near random generators", "Excerpt"],
    "code_none": "No indicator of randomly generated data was found in the static analysis (limit: dynamically "
                 "loaded or obfuscated code can be missed).",
    "feed": "Endpoints polled periodically",
    "s_eco": "Economic and product inconsistencies",
    "eco_cols": ["Excerpt from the site", "Rate", "Period", "Annualised (simple)"],
    "eco_none": "No return promise with an explicit period was found.",
    "periods": {"daily": "daily", "weekly": "weekly", "monthly": "monthly", "yearly": "yearly"},
    "behav": "Behavioural indicator",
    "behav_txt": "If a further payment is requested to unlock withdrawals, pay taxes, fees, gas, AML checks or a plan "
                 "upgrade, do not pay: it is a recurring advance-fee fraud pattern.",
    "s_ent": "Company, domain and regulatory framework",
    "ent_cols": ["Check", "Result", "Limit"],
    "dom_reg": "Domain registered",
    "dom_age": "Domain age",
    "dom_registrar": "Registrar",
    "dom_ns": "Nameservers",
    "dom_lim": "A young domain is a contextual red flag, not stand-alone proof.",
    "days": "{n} days",
    "declared": "Entity declared on the site",
    "none_found": "None found",
    "vies": "VIES (EU VAT number)",
    "gleif": "GLEIF (LEI)",
    "valid": "valid", "invalid": "invalid", "norecord": "no record", "unavail": "unavailable",
    "ent_lim": "Absence of a record proves nothing; absence of a warning is not an authorisation.",
    "manual_checks": "To verify manually",
    "manual_rows": [
        ["Official extract/certificate from the competent company registry",
         "Obtain the up-to-date official document (aggregator pages are not enough for judicial use)."],
        ["Registered corporate purpose and authorised activities vs the site's business model",
         "Compare the published purpose with what the site promises."],
        ["Authorisation/registration as a crypto-asset service provider",
         "ESMA MiCA registers and the national supervisory authority; for non-EU, the local regulator."],
        ["Regulator warnings", "National warning lists and IOSCO I-SCAN."],
    ],
    "to_verify": "To verify",
    "s_web": "Web surface and security checks",
    "web_cols": ["Item", "Observation"],
    "web_note": "Passive snapshot of the service, not a penetration test. No authentication, bypass, injection or "
                "destructive action was attempted. TLS protects transport; it does not certify economic reliability.",
    "present": "present", "absent": "absent",
    "legal_pages": "Legal pages",
    "legal_none": "No legal page reachable",
    "chars": "chars",
    "creds": "Credentials",
    "creds_txt": "If the password used on the site was reused elsewhere, change it everywhere now and enable "
                 "multi-factor authentication. Do not send further documents to the site.",
    "s_risk": "Risk matrix",
    "risk_cols": ["Indicator", "Severity", "Confidence", "Nature", "Basis"],
    "sev": {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"},
    "conf": {"high": "High", "medium-high": "Medium-high", "medium": "Medium", "low": "Low"},
    "kind": {"fact": "Fact", "interpretation": "Interpretation", "limit": "Limit"},
    "overall": "OVERALL ASSESSMENT",
    "overall_txt": "The assessment does not rest on a single clue but on the convergence of independent elements. "
                   "Heuristic score: {score}. The final decision rests with the analyst.",
    "s_act": "Recommended actions",
    "act_cols": ["Priority", "Action", "Goal"],
    "act_rows_always": [
        ["P0", "Do not send further funds, not even for fees, taxes, AML, gas or unlocking.", "Prevent further loss."],
        ["P0", "Keep chats, usernames, emails, URLs, receipts, balance screenshots and payment requests.",
         "Build a chain of evidence."],
        ["P0", "Change any reused passwords and enable MFA.", "Reduce account-takeover risk."],
    ],
    "act_tx": ["P0", "Open a scam/fraud case with the originating exchange or wallet provider now; attach the full "
                     "TxID and this report.", "Preserve timing, logs and possible cooperation with exchanges/authorities."],
    "act_police": ["P1", "File a report with the competent law enforcement ({p}), attaching full identifiers in a "
                         "confidential annex.", "Trigger formal investigative tools."],
    "act_reg": ["P1", "Report the entity to the financial supervisory authority ({r}).",
                "Have a possible unauthorised activity checked."],
    "recovery": "Fund recovery",
    "recovery_txt": "Confirmed blockchain transactions cannot be reversed unilaterally. Recovery may depend on "
                    "identifying the beneficiary, a freeze at a custodial party or an authority's order. Beware of "
                    "recovery agents who ask for upfront fees or promise guaranteed recovery.",
    "pack": "Minimum evidence package",
    "pack_items": ["Unredacted original files and their SHA-256.",
                   "Exchange history export and withdrawal receipt.",
                   "Full TxIDs and addresses in a separate confidential document.",
                   "Complete chats with timestamps, not only selective screenshots.",
                   "Site URL, account username, displayed terms and payment requests.",
                   "A written timeline of contacts, drafted while memories are fresh."],
    "app_a": "Appendix A - Reproducible technical details",
    "app_a_txt": "For privacy reasons identifiers are abbreviated in this copy; the copy for the authorities must add "
                 "an annex with the full values.",
    "app_a_rpc": "JSON-RPC calls used: eth_getCode, eth_getTransactionCount, eth_getBalance, "
                 "eth_getTransactionReceipt, eth_getBlockByNumber, eth_blockNumber, eth_call balanceOf(address).",
    "sel_cols": ["Selector", "Function", "Use"],
    "sel_rows": [["0xa9059cbb", "transfer(address,uint256)", "ERC-20 token transfers"],
                 ["0x095ea7b3", "approve(address,uint256)", "Allowance to a spender"],
                 ["0x70a08231", "balanceOf(address)", "Token balance of an address"]],
    "repeat": "Repeatability checks: verify receipt status = 1, decode target and uint256 from the input, compare the "
              "Transfer event in the logs, check eth_getCode = 0x to tell EOA from contract; record block, UTC "
              "timestamp and RPC endpoint.",
    "app_b": "Appendix B - References",
    "limits": "Limitations",
    "limits_items": ["Preliminary technical analysis: not legal advice nor a judicial expert report.",
                     "No certain attribution of wallet ownership.",
                     "No access to accounting, backend, databases, exchange orders or private keys.",
                     "The absence of a specific warning does not certify the operator.",
                     "On-chain balances and nonces are dynamic and represent the stated snapshot.",
                     "Automated heuristics (JavaScript, text, flow patterns) can produce false positives and must be "
                     "reviewed by an analyst.",
                     "For judicial use obtain up-to-date official extracts and certificates."],
    "final": "Final conclusion",
    "final_txt": {
        "critical": "On the available evidence, continuing to pay money or hand over data to the service is not "
                    "reasonable. The priority is to stop payments, preserve evidence and engage the exchange and "
                    "the competent authorities.",
        "high": "On the available evidence the risk level is high: avoid new payments, preserve evidence and "
                "follow up with the authorities and a lawyer.",
        "medium": "Risk signals emerged: suspend payments until independent checks on the operator's identity and "
                  "authorisations are done.",
        "low": "The checks performed show no strong signals, but the manual verifications listed are still needed "
               "before any decision.",
    },
    "police": {"IT": "Polizia Postale", "ES": "Policía Nacional / Guardia Civil", "PT": "Polícia Judiciária",
               "GB": "local police / national fraud reporting service", "US": "FBI IC3",
               "DE": "local police (Landeskriminalamt)", "FR": "police/gendarmerie and the Pharos platform",
               "BR": "Polícia Federal / Polícia Civil", "": "your country's police cybercrime unit"},
    "regulator": {"IT": "Consob", "ES": "CNMV", "PT": "CMVM / Banco de Portugal", "GB": "FCA", "US": "SEC / CFTC / FTC",
                  "DE": "BaFin", "FR": "AMF", "BR": "CVM / Banco Central do Brasil",
                  "": "your country's financial markets regulator"},
    "yes": "yes", "no": "no", "na": "n/a",
}


# --------------------------------------------------------------------------- helpers
def _fmt_num(x: float, lang: str, dec: int = 2) -> str:
    s = f"{x:,.{dec}f}"
    return s.replace(",", "X").replace(".", ",").replace("X", ".") if lang == "it" else s


def _fmt_date(iso: str, lang: str) -> str:
    try:
        d = date.fromisoformat(iso[:10])
    except ValueError:
        return iso
    m = MONTHS[lang][d.month - 1]
    return f"{d.day} {m} {d.year}" if lang == "it" else f"{m} {d.day}, {d.year}"


def _fmt_delay(sec) -> str:
    if sec is None:
        return ""
    sec = int(sec)
    if sec < 60:
        return f"{sec} s"
    if sec < 3600:
        return f"{sec // 60} min {sec % 60} s"
    return f"{sec // 3600} h {(sec % 3600) // 60} min"


def _styles() -> dict:
    base = dict(fontName="Helvetica", fontSize=9.2, leading=12.6, textColor=NAVY, alignment=TA_LEFT)
    return {
        "body": ParagraphStyle("body", **base),
        "small": ParagraphStyle("small", **{**base, "fontSize": 7.8, "leading": 10.2, "textColor": GREY}),
        "cell": ParagraphStyle("cell", **{**base, "fontSize": 8.2, "leading": 10.6}),
        "cellb": ParagraphStyle("cellb", **{**base, "fontName": "Helvetica-Bold", "fontSize": 8.2, "leading": 10.6}),
        "mono": ParagraphStyle("mono", **{**base, "fontName": "Courier", "fontSize": 7.2, "leading": 9.2}),
        "h1": ParagraphStyle("h1", **{**base, "fontName": "Helvetica-Bold", "fontSize": 15, "leading": 19,
                                      "spaceBefore": 14, "spaceAfter": 7, "keepWithNext": 1}),
        "h2": ParagraphStyle("h2", **{**base, "fontName": "Helvetica-Bold", "fontSize": 10.5, "leading": 14,
                                      "textColor": BLUE, "spaceBefore": 9, "spaceAfter": 4, "keepWithNext": 1}),
        "title": ParagraphStyle("title", **{**base, "fontName": "Helvetica-Bold", "fontSize": 19, "leading": 24}),
        "subtitle": ParagraphStyle("subtitle", **{**base, "fontSize": 11, "leading": 15, "textColor": GREY}),
        "bullet": ParagraphStyle("bullet", **{**base, "leftIndent": 12, "bulletIndent": 2, "spaceAfter": 2}),
    }


class FlowDiagram(Flowable):
    """Diagramma orizzontale dei passaggi di fondi: nodi come riquadri, frecce con importo e ritardo."""

    def __init__(self, nodes, edges, lang, redact, width=W, height=62):
        super().__init__()
        self.nodes, self.edges, self.lang, self.redact = nodes, edges, lang, redact
        self.width, self.height = width, height

    def wrap(self, aw, ah):
        return self.width, self.height

    def draw(self):
        c = self.canv
        n = len(self.nodes)
        gap = 15 * mm if n > 1 else 0
        bw = min(34 * mm, (self.width - (n - 1) * gap) / n)
        gap = (self.width - n * bw) / (n - 1) if n > 1 else 0
        y, bh = 12, 36
        for i, nd in enumerate(self.nodes):
            x = i * (bw + gap)
            last = i == n - 1 and n > 2
            c.setStrokeColor(colors.HexColor("#b91c1c") if last else colors.HexColor("#94a3b8"))
            c.setFillColor(LIGHT)
            c.setLineWidth(1.1 if last else 0.8)
            c.roundRect(x, y, bw, bh, 4, stroke=1, fill=1)
            c.setFillColor(NAVY)
            c.setFont("Helvetica-Bold", 6.8)
            c.drawCentredString(x + bw / 2, y + bh - 11, nd["label"][:18])
            c.setFont("Helvetica", 6.2)
            c.setFillColor(GREY)
            c.drawCentredString(x + bw / 2, y + bh - 20, (nd.get("role") or "")[:24])
            addr = nd["address"]
            addr = short(addr) if self.redact else short(addr, 8, 6)
            c.setFont("Courier", 5.9)
            c.setFillColor(NAVY)
            c.drawCentredString(x + bw / 2, y + 5, addr)
        for i, e in enumerate(self.edges[: n - 1]):
            x1 = i * (bw + gap) + bw + 1.5
            x2 = (i + 1) * (bw + gap) - 1.5
            ym = y + bh / 2
            c.setStrokeColor(BLUE)
            c.setFillColor(BLUE)
            c.setLineWidth(1)
            c.line(x1, ym, x2 - 4, ym)
            p = c.beginPath()
            p.moveTo(x2, ym)
            p.lineTo(x2 - 5, ym + 2.6)
            p.lineTo(x2 - 5, ym - 2.6)
            p.close()
            c.drawPath(p, stroke=0, fill=1)
            c.setFillColor(NAVY)
            c.setFont("Helvetica-Bold", 6.4)
            c.drawCentredString((x1 + x2) / 2, ym + 5, _fmt_num(e["amount"], self.lang))
            c.setFont("Helvetica", 5.8)
            c.setFillColor(GREY)
            c.drawCentredString((x1 + x2) / 2, ym - 9, e["token"])
            d = _fmt_delay(e.get("delay_s"))
            if d:
                c.drawCentredString((x1 + x2) / 2, ym - 16, d)


# --------------------------------------------------------------------------- costruzione
def render(case: dict, path: str, lang: str | None = None, redact: bool | None = None) -> str:
    meta = case["meta"]
    lang = lang or meta.get("lang", "it")
    T = S.get(lang, S["it"])
    redact = meta.get("redact", True) if redact is None else redact
    st = _styles()
    fs = all_findings(case)
    level, score = assess(fs)
    lvl_name = T["levels"][level]
    target = meta.get("target", "target")
    addr_f = (lambda a: short(a)) if redact else (lambda a: a)
    tx_f = (lambda a: short(a, 10, 7)) if redact else (lambda a: a)

    def P(text, style="body", raw=False):
        return Paragraph(text if raw else escape(str(text)), st[style])

    def sev_html(sev):
        return f'<font color="{SEV_COLOR[sev]}"><b>{escape(T["sev"][sev])}</b></font>'

    def table(rows, widths, header=True, zebra=True, extra=None):
        t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
        style = [("GRID", (0, 0), (-1, -1), 0.4, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                 ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                 ("TOPPADDING", (0, 0), (-1, -1), 3.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5)]
        if header:
            style.append(("BACKGROUND", (0, 0), (-1, 0), HEAD))
        if zebra:
            for r in range(1 if header else 0, len(rows)):
                if r % 2 == 0:
                    style.append(("BACKGROUND", (0, r), (-1, r), colors.HexColor("#f8fafc")))
        t.setStyle(TableStyle(style + (extra or [])))
        return t

    def hrow(cols):
        return [P(c, "cellb") for c in cols]

    def box(title, text_html, color="#fff7e6", border="#f59e0b"):
        t = Table([[P(f"<b>{escape(title)}</b>", "cell", raw=True)], [P(text_html, "cell", raw=True)]],
                  colWidths=[W])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(color)),
                               ("LINEBEFORE", (0, 0), (0, -1), 3, colors.HexColor(border)),
                               ("LEFTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 4),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
        return t

    story: list = []
    sec = [0]

    def H1(title):
        sec[0] += 1
        story.append(Paragraph(f"{sec[0]}. {escape(title)}", st["h1"]))

    def H2(title):
        story.append(Paragraph(escape(title), st["h2"]))

    # ---- copertina / esito
    story.append(P(T["title"], "title"))
    story.append(Spacer(1, 3))
    story.append(P(T["subtitle"].format(target=target), "subtitle"))
    story.append(Spacer(1, 10))
    banner = Table([[P(f'<font color="white" size="8">{escape(T["outcome"])}</font>', "cell", raw=True)],
                    [P(f'<font color="white" size="20"><b>{escape(lvl_name)}</b></font>', "cell", raw=True)],
                    [P(f'<font color="white" size="9">{escape(T["conclusion"][level])}</font>', "cell", raw=True)]],
                   colWidths=[W])
    banner.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(LEVEL_COLOR[level])),
                                ("LEFTPADDING", (0, 0), (-1, -1), 12), ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                                ("TOPPADDING", (0, 0), (-1, 0), 9), ("BOTTOMPADDING", (0, -1), (-1, -1), 10),
                                ("TOPPADDING", (0, 1), (-1, -1), 3)]))
    story.append(banner)
    story.append(Spacer(1, 7))
    bits = [T["version"].format(v=meta.get("report_version", "1.0"), d=_fmt_date(meta["analysis_date"], lang),
                                tz=meta.get("timezone", "UTC"))]
    if meta.get("case_ref"):
        bits.append(T["ref"].format(r=meta["case_ref"]))
    if meta.get("analyst"):
        bits.append(T["analyst"].format(a=meta["analyst"]))
    story.append(P(" | ".join(bits), "small"))
    story.append(P(T["conf_doc"] if redact else T["conf_doc_full"], "small"))

    # ---- 1. sintesi
    H1(T["s_exec"])
    H2(T["verdict"])
    top = [x for x in fs if x.kind != "limit" and SEV_ORDER[x.severity] >= 2]
    top.sort(key=lambda x: (-SEV_ORDER[x.severity], x.id))
    items = ", ".join(render_finding(x, lang)[0].lower() for x in top[:4]) or "-"
    story.append(P(T["verdict_txt"].format(lvl=lvl_name.lower(), score=score, items=items)))

    # ---- sintesi in parole semplici, per chi legge senza background tecnico
    H2(T["plain_title"])
    story.append(P(T["plain_opening"].get(level, T["plain_opening"]["medium"])))
    plain_pts = [x for x in top[:5]]
    if plain_pts:
        story.append(Spacer(1, 2))
        story.append(P(T["plain_points_intro"]))
        for x in plain_pts:
            t_, _ = render_finding(x, lang)
            story.append(Paragraph(escape(t_), st["bullet"], bulletText="•"))
    else:
        story.append(Spacer(1, 2))
        story.append(P(T["plain_none"]))
    story.append(Spacer(1, 2))
    story.append(P(T["plain_closing"], "small"))

    H2(T["why"])
    why = [x for x in fs if x.kind != "limit" and SEV_ORDER[x.severity] >= 3][:7] or top[:4]
    rows = [hrow(T["why_cols"])]
    for x in why:
        t_, d_ = render_finding(x, lang)
        rows.append([P(t_, "cellb"), P(d_, "cell"),
                     P(f'<font color="{SEV_COLOR[x.severity]}"><b>{escape(T["weights"][x.severity])}</b></font>',
                       "cell", raw=True)])
    if len(rows) > 1:
        story.append(table(rows, [42 * mm, 100 * mm, 28 * mm]))
    if case.get("victim_tx"):
        story.append(Spacer(1, 6))
        H2(T["proves"])
        story.append(box(T["proves"], T["proves_txt"]))

    # ---- 2. metodo
    H1(T["s_method"])
    story.append(P(T["method_txt"], raw=True))
    H2(T["sources"])
    for s_ in case.get("sources_used", []):
        story.append(Paragraph(escape(s_), st["bullet"], bulletText="•"))
    if redact:
        H2(T["privacy"])
        story.append(table([hrow(T["priv_cols"])] + [[P(a, "cell"), P(b, "cell")] for a, b in T["priv_rows"]],
                           [60 * mm, 110 * mm]))
    if case.get("evidence"):
        H2(T["hash_cols"][1])
        ev = [hrow(T["hash_cols"])] + [[P(e["name"], "cell"), P(e["sha256"], "mono")] for e in case["evidence"][:30]]
        story.append(table(ev, [55 * mm, 115 * mm]))
        story.append(Spacer(1, 3))
        story.append(P(T["hash_note"], "small"))

    # ---- 3. tx
    vt = case.get("victim_tx")
    if vt:
        H1(T["s_tx"])
        vals = [vt["chain"].upper(), vt["token"], f'{_fmt_num(vt["amount"], lang)} {vt["token"]}',
                addr_f(vt["from"]), addr_f(vt["to"]), str(vt.get("block", "")), vt.get("status", ""),
                tx_f(vt["tx"])]
        rows = [hrow(T["tx_cols"])] + [[P(k, "cellb"), P(v, "mono" if k in T["tx_fields"][3:5] + [T["tx_fields"][7]]
                                                          else "cell")] for k, v in zip(T["tx_fields"], vals)]
        story.append(table(rows, [40 * mm, 130 * mm]))

    # ---- 4. ricostruzione on-chain
    flow = case.get("flow")
    if flow:
        H1(T["s_chain"])
        story.append(P(T["chain_txt"]))
        story.append(Spacer(1, 6))
        story.append(FlowDiagram(flow["nodes"], flow["edges"], lang, redact))
        story.append(Spacer(1, 4))
        rows = [hrow(T["phase_cols"])]
        nodes = flow["nodes"]
        for i, e in enumerate(flow["edges"]):
            if i + 1 >= len(nodes):
                break
            a, b = nodes[i], nodes[i + 1]
            delay = _fmt_delay(e.get("delay_s"))
            txt = (f'{a["label"]} -> {b["label"]}: {_fmt_num(e["amount"], lang)} {e["token"]}'
                   + (f" (+{delay})" if delay else ""))
            rows.append([P(str(i + 1), "cell"), P(txt, "cell"), P(T["confirmed"], "cell")])
        story.append(table(rows, [16 * mm, 128 * mm, 26 * mm]))
        if not flow.get("traced"):
            story.append(Spacer(1, 3))
            story.append(P(T["not_traced"], "small"))
        elif len(flow["edges"]) > 1:
            H2(T["chain_concl"])
            story.append(P(T["chain_concl_txt"]))
        story.append(Spacer(1, 4))
        story.append(table([hrow(T["proven_cols"])] + [[P(a, "cellb"), P(b, "cell")] for a, b in T["proven_rows"]],
                           [38 * mm, 132 * mm]))

    # ---- 5. wallet
    if case.get("wallets"):
        H1(T["s_wallets"])
        rows = [hrow(T["wallet_cols"])]
        for w in case["wallets"]:
            s_ = w.get("snapshot") or {}
            ch = s_.get("chain", "")
            if ch in ("btc", "ltc", "doge"):
                act = f'{s_.get("tx_count", 0)} tx'
                bal = f'{_fmt_num(s_.get("balance", 0), lang, 4)} {ch.upper()} (rx {_fmt_num(s_.get("received", 0), lang)})'
            else:
                act = str(s_.get("nonce", s_.get("tx_sampled", "")))
                toks = ", ".join(f"{_fmt_num(v, lang)} {k}" for k, v in (s_.get("tokens") or {}).items())
                nat = (f'{s_.get("native", 0):.6g}'.replace(".", "," if lang == "it" else ".") + f' {s_.get("native_symbol", "")}') \
                    if "native" in s_ else ""
                bal = "; ".join(x for x in (toks, nat) if x)
            rows.append([P(f'{w["label"]}<br/><font size="6.5" color="#64748b">{escape(ch.upper())}'
                           f'{" - " + escape(w["role"]) if w.get("role") else ""}</font>', "cell", raw=True),
                         P(addr_f(w["address"]), "mono"), P(str(s_.get("type", "")), "cell"), P(act, "cell"),
                         P(bal, "cell"), P(w.get("reading", ""), "cell")])
        story.append(table(rows, [24 * mm, 33 * mm, 15 * mm, 15 * mm, 38 * mm, 45 * mm]))
        story.append(Spacer(1, 4))
        story.append(box(T["poison"], escape(T["poison_txt"]), "#f1f5f9", "#64748b"))

    # ---- 6. codice
    site = case.get("site")
    if site and site.get("status"):
        H1(T["s_code"])
        hits = site.get("random_hits", [])
        if hits:
            rows = [hrow(T["code_cols"])]
            for h in hits[:8]:
                rows.append([P(h["file"], "cell"), P(", ".join(h["keywords"]), "cell"), P(h["snippet"], "mono")])
            story.append(table(rows, [32 * mm, 38 * mm, 100 * mm]))
        else:
            story.append(P(T["code_none"]))
        if site.get("feed"):
            H2(T["feed"])
            for e in site["feed"][:6]:
                story.append(Paragraph(escape(e), st["bullet"], bulletText="•"))

        # ---- 7. economia
        H1(T["s_eco"])
        rates = site.get("text", {}).get("rates", [])
        if rates:
            rows = [hrow(T["eco_cols"])]
            for r in rates[:10]:
                rows.append([P(r["snippet"], "cell"), P(f'{r["rate"]:g}%', "cell"),
                             P(T["periods"][r["period"]], "cell"), P(f'{r["annual"]:g}%', "cell")])
            story.append(table(rows, [84 * mm, 18 * mm, 28 * mm, 40 * mm]))
        else:
            story.append(P(T["eco_none"]))
        for key in ("guarantees", "referral", "pressure"):
            vals = site.get("text", {}).get(key, [])
            if vals:
                story.append(Spacer(1, 3))
                story.append(Paragraph(f"<b>{key}:</b> {escape(', '.join(vals))}", st["body"]))
        story.append(Spacer(1, 4))
        story.append(box(T["behav"], escape(T["behav_txt"])))

    # ---- 8. società / dominio
    dom, ent = case.get("domain"), case.get("entity")
    if dom or ent or site:
        H1(T["s_ent"])
        rows = [hrow(T["ent_cols"])]
        if dom:
            if dom.get("available"):
                rows.append([P(T["dom_reg"], "cellb"), P(_fmt_date(dom.get("registered") or "", lang), "cell"),
                             P(T["dom_lim"], "small")])
                if dom.get("age_days") is not None:
                    rows.append([P(T["dom_age"], "cellb"), P(T["days"].format(n=dom["age_days"]), "cell"), P("", "cell")])
                if dom.get("registrar"):
                    rows.append([P(T["dom_registrar"], "cellb"), P(dom["registrar"], "cell"), P("", "cell")])
                if dom.get("nameservers"):
                    rows.append([P(T["dom_ns"], "cellb"), P(", ".join(dom["nameservers"][:4]), "cell"), P("", "cell")])
            else:
                rows.append([P("RDAP", "cellb"), P(T["unavail"], "cell"), P("", "cell")])
        if site:
            cm = site.get("company_mentions", {})
            dec = "; ".join(cm.get("names", []) + cm.get("ids", [])) or T["none_found"]
            rows.append([P(T["declared"], "cellb"), P(dec, "cell"), P("", "cell")])
        if ent:
            v = ent.get("vies")
            if v is not None:
                res_ = (T["valid"] if v["valid"] else T["invalid"]) + (f' - {v["name"]}' if v.get("name") else "")
                rows.append([P(T["vies"], "cellb"), P(res_, "cell"), P(T["ent_lim"], "small")])
            if "gleif" in ent:
                g = ent["gleif"]
                res_ = "; ".join(f'{x["name"]} ({x["lei"]})' for x in g[:2]) if g else T["norecord"]
                rows.append([P(T["gleif"], "cellb"), P(res_, "cell"), P("", "cell")])
            cj = ent.get("cnpj")
            if cj:
                res_ = f'{cj.get("name") or T["na"]} - {cj.get("status") or T["na"]}'
                if cj.get("opened"):
                    res_ += f' ({_fmt_date(cj["opened"], lang)})'
                rows.append([P(T["cnpj"], "cellb"), P(res_, "cell"), P("", "cell")])
            for key, label in (("opencorporates", "OpenCorporates"), ("companies_house", "Companies House"),
                               ("opensanctions", "OpenSanctions")):
                if key in ent:
                    arr = ent[key]
                    res_ = "; ".join(str(x.get("name")) for x in arr[:2]) if arr else T["norecord"]
                    rows.append([P(label, "cellb"), P(res_, "cell"), P("", "cell")])
        if len(rows) > 1:
            story.append(table(rows, [42 * mm, 70 * mm, 58 * mm]))
        H2(T["manual_checks"])
        mrows = [hrow(T["ent_cols"][:2] + [""])]
        mrows = [hrow([T["ent_cols"][0], T["manual_checks"], T["ent_cols"][1]])] + \
                [[P(a, "cell"), P(b, "cell"), P(T["to_verify"], "cell")] for a, b in T["manual_rows"]]
        story.append(table(mrows, [62 * mm, 82 * mm, 26 * mm]))
        vs = (ent or {}).get("verification_sources") or []
        if vs:
            H2(T["ver_sources"])
            if (ent or {}).get("country"):
                story.append(P(T["country_hint"].format(c=ent["country"]), "small"))
                if ent.get("country_inferred_from"):
                    story.append(P(T["country_inferred"].format(src=ent["country_inferred_from"]), "small"))
            story.append(table([hrow(T["ver_cols"])] + [[P(a, "cell"), P(b, "mono")] for a, b in vs], [78 * mm, 92 * mm]))
        geo = (ent or {}).get("geo")
        if geo:
            H2(T["geo_title"])
            prec = T["geo_precise"] if geo.get("precise") else T["geo_vague"]
            grows = [hrow(T["geo_cols"]),
                     [P(T["geo_addr"], "cellb"), P(geo.get("query", "n/d"), "cell")],
                     [P(T["geo_resolved"], "cellb"), P(geo.get("display_name") or "n/d", "cell")],
                     [P(T["geo_country"], "cellb"), P((geo.get("country_code") or "n/d").upper(), "cell")],
                     [P(T["geo_precision"], "cellb"), P(prec, "cell")]]
            story.append(table(grows, [55 * mm, 115 * mm]))
            story.append(Spacer(1, 2))
            story.append(P(T["geo_note"], "small"))

    # ---- 9. web
    if site and site.get("status"):
        H1(T["s_web"])
        rows = [hrow(T["web_cols"])]
        srv = " ".join(x for x in (site.get("server", ""), site.get("x_powered_by", "")) if x) or T["na"]
        rows.append([P("Server", "cellb"), P(srv, "cell")])
        sh = ", ".join(f'{k}: {T["present"] if v else T["absent"]}' for k, v in site.get("security_headers", {}).items())
        rows.append([P("Security headers", "cellb"), P(sh, "cell")])
        cors = site.get("cors", {})
        rows.append([P("CORS", "cellb"), P(f'ACAO={cors.get("acao") or T["na"]}; ACAC={cors.get("acac") or T["na"]}',
                                           "cell")])
        rows.append([P("Cookie", "cellb"), P("; ".join(site.get("cookie_issues", [])) or "-", "cell")])
        lp = site.get("legal_pages", [])
        rows.append([P(T["legal_pages"], "cellb"),
                     P("; ".join(f'{x["url"]} ({x["chars"]} {T["chars"]})' for x in lp) or T["legal_none"], "cell")])
        story.append(table(rows, [38 * mm, 132 * mm]))
        eps = (site.get("endpoints") or []) + (site.get("pages") or [])
        if eps:
            H2(T["ep_title"])
            erows = [hrow(T["ep_cols"])]
            for e in eps:
                shown = ", ".join((short(a) if redact else a) for a in e.get("addresses", [])) or "-"
                status = str(e.get("status") or "-") + (" (login)" if e.get("auth_required") else "")
                cats = ", ".join(e.get("categories", [])) or ("-" if e.get("status") else "")
                erows.append([P(e["url"], "mono"), P(status, "cell"), P(shown, "mono"), P(cats, "cell")])
            story.append(table(erows, [68 * mm, 15 * mm, 38 * mm, 49 * mm]))
            story.append(P(T["ep_note"], "small"))
        story.append(Spacer(1, 3))
        story.append(P(T["web_note"], "small"))
        story.append(Spacer(1, 4))
        story.append(box(T["creds"], escape(T["creds_txt"]), "#f1f5f9", "#64748b"))

    # ---- sezioni aggiuntive (dati di osint_recon.py)
    extra = case.get("extra_sections") or []
    if extra:
        H1(T["s_extra"])
        for xs in extra:
            H2(xs["title"])
            ncol = len(xs["cols"])
            first = 46 * mm
            widths = [first] + [(170 * mm - first) / max(1, ncol - 1)] * (ncol - 1)
            story.append(table([hrow(xs["cols"])] + [[P(str(c), "cell") for c in r] for r in xs["rows"]], widths))
            if xs.get("note"):
                story.append(Spacer(1, 2))
                story.append(P(xs["note"], "small"))
            story.append(Spacer(1, 4))

    # ---- 10. matrice
    H1(T["s_risk"])
    rows = [hrow(T["risk_cols"])]
    for x in sorted(fs, key=lambda z: (-SEV_ORDER[z.severity], z.id)):
        t_, _d = render_finding(x, lang)
        rows.append([P(f'{x.id} - {t_}', "cell"), P(sev_html(x.severity), "cell", raw=True),
                     P(T["conf"][x.confidence], "cell"), P(T["kind"][x.kind], "cell"), P(x.basis, "cell")])
    story.append(table(rows, [66 * mm, 20 * mm, 22 * mm, 24 * mm, 38 * mm]))
    story.append(Spacer(1, 6))
    ob = Table([[P(f'<font color="white" size="8">{escape(T["overall"])}</font>', "cell", raw=True)],
                [P(f'<font color="white" size="14"><b>{escape(lvl_name)}</b></font>', "cell", raw=True)],
                [P(f'<font color="white" size="8.5">{escape(T["overall_txt"].format(score=score))}</font>', "cell",
                   raw=True)]], colWidths=[W])
    ob.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(LEVEL_COLOR[level])),
                            ("LEFTPADDING", (0, 0), (-1, -1), 10), ("TOPPADDING", (0, 0), (-1, -1), 3),
                            ("BOTTOMPADDING", (0, -1), (-1, -1), 8)]))
    story.append(KeepTogether([ob]))

    # ---- 11. azioni
    H1(T["s_act"])
    cc = (meta.get("reporter_country") or "").upper()
    police = T["police"].get(cc, T["police"][""])
    reg = T["regulator"].get(cc)
    if not reg and cc in registries.COUNTRIES:
        reg = registries.COUNTRIES[cc]["regulator"][0].split(" - ")[0]
    reg = reg or T["regulator"][""]
    acts = list(T["act_rows_always"])
    if vt:
        acts.insert(1, T["act_tx"])
    acts.append([T["act_police"][0], T["act_police"][1].format(p=police), T["act_police"][2]])
    acts.append([T["act_reg"][0], T["act_reg"][1].format(r=reg), T["act_reg"][2]])
    story.append(table([hrow(T["act_cols"])] + [[P(a, "cellb"), P(b, "cell"), P(c_, "cell")] for a, b, c_ in acts],
                       [18 * mm, 98 * mm, 54 * mm]))
    story.append(Spacer(1, 5))
    story.append(box(T["recovery"], escape(T["recovery_txt"])))
    H2(T["pack"])
    for it in T["pack_items"]:
        story.append(Paragraph(escape(it), st["bullet"], bulletText="•"))

    # ---- appendici
    story.append(PageBreak())
    story.append(Paragraph(escape(T["app_a"]), st["h1"]))
    story.append(P(T["app_a_txt"]))
    arows = [hrow(["Item", "Ref"])]
    if vt:
        arows.append([P("TX", "cellb"), P(tx_f(vt["tx"]), "mono")])
    for w in case.get("wallets", []):
        arows.append([P(w["label"], "cellb"), P(addr_f(w["address"]) + "  [" + (w.get("snapshot") or {}).get("chain", "")
                                                 + "]", "mono")])
    for h in (flow or {}).get("hops", []):
        arows.append([P("TX hop", "cellb"), P(tx_f(h["tx"]), "mono")])
    if len(arows) > 1:
        story.append(table(arows, [38 * mm, 132 * mm]))
    if vt or any((w.get("snapshot") or {}).get("chain") in ("bsc", "eth", "polygon", "arbitrum", "base", "optimism", "avalanche")
                 for w in case.get("wallets", [])):
        story.append(Spacer(1, 4))
        story.append(P(T["app_a_rpc"], "small"))
        story.append(Spacer(1, 3))
        story.append(table([hrow(T["sel_cols"])] + [[P(a, "mono"), P(b, "cell"), P(c_, "cell")] for a, b, c_ in
                                                     T["sel_rows"]], [32 * mm, 60 * mm, 78 * mm]))
        story.append(Spacer(1, 3))
        story.append(P(T["repeat"], "small"))
    story.append(Paragraph(escape(T["app_b"]), st["h1"]))
    for r_ in T["refs"]:
        story.append(Paragraph(escape(r_), st["bullet"], bulletText="•"))
    story.append(Paragraph(escape(T["limits"]), st["h1"]))
    for it in T["limits_items"]:
        story.append(Paragraph(escape(it), st["bullet"], bulletText="•"))
    story.append(Spacer(1, 8))
    story.append(box(T["final"], escape(T["final_txt"][level]), "#f1f5f9", LEVEL_COLOR[level]))

    # ---- documento
    def on_page(canv, doc):
        canv.saveState()
        canv.setFont("Helvetica-Bold", 7.5)
        canv.setFillColor(NAVY)
        canv.drawString(20 * mm, A4[1] - 12 * mm, T["hdr"].format(t=target.upper())[:95])
        canv.setFont("Helvetica", 7.5)
        canv.setFillColor(GREY)
        canv.drawRightString(A4[0] - 20 * mm, A4[1] - 12 * mm, T["hdr_r"])
        canv.setStrokeColor(LINE)
        canv.line(20 * mm, A4[1] - 14 * mm, A4[0] - 20 * mm, A4[1] - 14 * mm)
        foot = T["ftr"].format(d=_fmt_date(meta["analysis_date"], lang)) + (T["ftr_priv"] if redact else "")
        canv.drawString(20 * mm, 10 * mm, foot)
        canv.drawRightString(A4[0] - 20 * mm, 10 * mm, T["page"].format(n=doc.page))
        canv.restoreState()

    doc = BaseDocTemplate(path, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm, topMargin=20 * mm,
                          bottomMargin=17 * mm, title=f"{T['title']} - {target}",
                          author=meta.get("analyst") or f"osintr-ext {VERSION}", subject=target)
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="f", leftPadding=0, rightPadding=0,
                  topPadding=0, bottomPadding=0)
    doc.addPageTemplates([PageTemplate(id="p", frames=[frame], onPage=on_page)])
    doc.build(story)
    return path
