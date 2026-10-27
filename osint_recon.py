#!/usr/bin/env python3
"""
osint_recon.py - Tool OSINT general-purpose per domini, email e numeri di telefono
Progettato per girare su iSH (Alpine Linux) su iOS.

Uso:
    python3 osint_recon.py dominio.com
    python3 osint_recon.py nome@esempio.com
    python3 osint_recon.py +391234567890
    python3 osint_recon.py 12.345.678/0001-90       # CNPJ brasiliano
    python3 osint_recon.py IT02117980405            # Partita IVA italiana/UE
    python3 osint_recon.py dominio.com --no-analyze      # salta la sintesi Gemini
    python3 osint_recon.py dominio.com --output ./report  # cartella output custom

Setup (su iSH):
    apk add python3 py3-pip whois
    pip install requests dnspython phonenumbers tqdm holehe socialscan pypdf exifread --break-system-packages
    export GOOGLE_API_KEY="la-tua-chiave-di-ai-studio"
    export ABUSEIPDB_API_KEY="la-tua-chiave-abuseipdb"   # opzionale
    export INTELX_API_KEY="la-tua-chiave-intelx"         # opzionale (dark web/leak)
    export ETHERSCAN_API_KEY="la-tua-chiave-etherscan"   # opzionale (saldo wallet ETH)
    export TRADE_GOV_API_KEY="la-tua-chiave-tradegov"    # opzionale (screening sanzioni)
    export CENSYS_API_TOKEN="la-tua-chiave-censys"       # opzionale (porte/servizi esposti - A PAGAMENTO da metà 2026)
    export ZOOMEYE_API_KEY="la-tua-chiave-zoomeye"       # opzionale (porte/servizi esposti)

Note:
    - whois usa il comando di sistema `whois` (apk add whois) se presente,
      altrimenti viene saltato con un avviso.
    - holehe (email check) è opzionale: se non installato, il modulo segnala
      l'errore e la scansione continua senza bloccarsi.
    - Il dorking e la ricerca Telegram usano DuckDuckGo HTML (nessuna API key
      richiesta) - da usare con moderazione per non incorrere in rate-limit.
    - Tutte le fonti usate sono pubbliche e gratuite (crt.sh, Wayback Machine,
      ip-api.com, hackertarget.com, DuckDuckGo). Alcune hanno rate-limit: in
      caso di errore il tool continua comunque con gli altri moduli.
"""

import argparse
import glob
import json
import os
import re
import socket
import ssl
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

import requests

try:
    import dns.resolver
    import dns.zone
    import dns.query
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone as pn_timezone
    HAVE_PHONENUMBERS = True
except ImportError:
    HAVE_PHONENUMBERS = False

try:
    from tqdm import tqdm
    HAVE_TQDM = True
except ImportError:
    HAVE_TQDM = False


REQUEST_TIMEOUT = 10
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; osint-recon/1.0)"}

# User-Agent rotanti per le richieste a DuckDuckGo (riduce probabilità di rate-limit/blocchi)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

import random


def random_headers():
    return {"User-Agent": random.choice(USER_AGENTS)}


# Caratteri Unicode invisibili/di controllo che spesso finiscono nel testo copiato
# da app di messaggistica (es. WhatsApp/iOS aggiunge marcatori di direzione bidi
# come \u202a...\u202c attorno ai numeri di telefono). Vanno rimossi PRIMA di
# qualsiasi rilevamento del tipo di target, altrimenti un numero valido viene
# scambiato per un dominio rotto.
INVISIBLE_CHARS_RE = re.compile(
    "[\u200b\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e\ufeff]"
)


def sanitize_target(raw):
    cleaned = INVISIBLE_CHARS_RE.sub("", raw)
    return cleaned.strip()


# ---------------------------------------------------------------------------
# Sistema di configurazione persistente (~/.osintr/config.json)
# Le chiavi API vengono lette PRIMA dalle variabili d'ambiente (compatibilità con
# chi le usava già così), poi dal file di configurazione salvato con --setup.
# Questo evita di dover fare 'export' ad ogni sessione e di dover incollare
# chiavi in chat per chiedere aiuto a configurarle.
# ---------------------------------------------------------------------------

CONFIG_DIR = os.path.expanduser("~/.osintr")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")

CONFIG_KEYS = [
    ("GOOGLE_API_KEY", "Google AI Studio (sintesi Gemini)", "https://aistudio.google.com"),
    ("ABUSEIPDB_API_KEY", "AbuseIPDB (reputazione IP)", "https://www.abuseipdb.com"),
    ("INTELX_API_KEY", "IntelligenceX (dark web/leak)", "https://intelx.io/signup"),
    ("ETHERSCAN_API_KEY", "Etherscan (saldo wallet Ethereum)", "https://etherscan.io/apis"),
    ("TRADE_GOV_API_KEY", "Trade.gov (screening sanzioni)", "https://api.data.gov/signup"),
    ("CENSYS_API_TOKEN", "Censys (porte/servizi esposti - a pagamento)", "https://accounts.censys.io/register"),
    ("ZOOMEYE_API_KEY", "ZoomEye (porte/servizi esposti)", "https://www.zoomeye.org"),
    ("INSTAGRAM_SESSION_ID", "Instagram (Toutatis - cookie sessionid del tuo login)", "vedi documentazione Toutatis"),
]


def load_config():
    if not os.path.exists(CONFIG_PATH):
        return {}
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_config(config):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
    try:
        os.chmod(CONFIG_PATH, 0o600)  # solo il proprietario può leggerlo (contiene chiavi)
    except Exception:
        pass  # su alcuni filesystem (es. iSH) chmod potrebbe non essere supportato appieno


def get_api_key(name):
    """Cerca la chiave prima nell'ambiente (export), poi nel file di configurazione
    salvato con --setup. Ordine scelto per compatibilità con chi le aveva già impostate
    manualmente prima che esistesse questo sistema."""
    env_val = os.environ.get(name)
    if env_val:
        return env_val
    config = load_config()
    return config.get(name) or None


ISO_COUNTRIES = {"IT", "ES", "PT", "FR", "DE", "NL", "BE", "IE", "GB", "CH", "AT", "LU", "MT", "CY", "LT", "EE",
                 "PL", "CZ", "SE", "DK", "NO", "FI", "GR", "US", "CA", "MX", "BR", "AR", "CL", "CO", "AU", "NZ",
                 "SG", "HK", "JP", "KR", "IN", "AE", "TR", "ZA", "NG", "SC", "VC", "VG", "KY", "RO", "BG", "HR",
                 "SI", "SK", "LV"}


def get_reporter_country():
    """Paese di chi segnala (per scegliere le autorita' competenti nel PDF): prima l'ambiente/config salvata con
    --setup, altrimenti lo chiede una volta sola (solo se il terminale e' interattivo) e la salva per le prossime
    scansioni. Non viene mai dedotto dall'IP: con Tor o una VPN sarebbe sbagliato, e non e' comunque un dato che
    un sito possa rivelare in modo affidabile."""
    env_val = os.environ.get("OSINTR_REPORTER_COUNTRY")
    if env_val:
        return env_val.strip().upper()
    config = load_config()
    saved = config.get("REPORTER_COUNTRY")
    if saved:
        return saved
    if not sys.stdin.isatty():
        return None   # non interattivo (script, cron): non blocca in attesa di input
    print("\nPer sapere a quali autorita' indicare nel rapporto PDF, serve il tuo paese (es. IT, ES, BR).")
    print("Te lo chiedo una volta sola: verra' salvato per le prossime scansioni (modificabile con --setup).")
    try:
        val = input("Il tuo paese (codice ISO a 2 lettere, INVIO per saltare): ").strip().upper()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if not val:
        return None
    if val not in ISO_COUNTRIES:
        print(f"[!] '{val}' non è tra i codici noti; lo salvo comunque così come l'hai scritto.")
    config["REPORTER_COUNTRY"] = val
    save_config(config)
    return val


def run_setup_wizard():
    """Wizard interattivo: chiede ogni chiave una volta sola e la salva in modo
    permanente in ~/.osintr/config.json - da quel momento tutte le scansioni la
    trovano automaticamente, senza bisogno di 'export' o di incollarla in chat."""
    print("=" * 60)
    print("CONFIGURAZIONE OSINTR")
    print("=" * 60)
    print(f"Le chiavi verranno salvate in: {CONFIG_PATH}")
    print("(file leggibile solo dal tuo utente, mai condiviso con nessuno)")
    print("Premi INVIO per saltare una chiave che non hai o non vuoi impostare ora.\n")

    config = load_config()
    current_rc = config.get("REPORTER_COUNTRY")
    status = f" [attualmente: {current_rc}]" if current_rc else " [non impostato]"
    print(f"\nIl tuo paese, per le autorita' competenti nel rapporto PDF{status}")
    try:
        rc = input("  Codice ISO a 2 lettere (es. IT), INVIO per mantenere/saltare: ").strip().upper()
    except (EOFError, KeyboardInterrupt):
        rc = ""
    if rc:
        config["REPORTER_COUNTRY"] = rc

    for key_name, description, signup_url in CONFIG_KEYS:
        current = config.get(key_name)
        status = " [già impostata, INVIO per mantenerla]" if current else " [non impostata]"
        print(f"\n{description}{status}")
        print(f"  Registrazione: {signup_url}")
        try:
            value = input(f"  {key_name}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nConfigurazione interrotta.")
            break
        if value:
            config[key_name] = value
        # se vuoto e già presente, resta quella salvata in precedenza

    save_config(config)
    print(f"\nConfigurazione salvata in {CONFIG_PATH}")
    configured = [k for k, _, _ in CONFIG_KEYS if config.get(k)]
    print(f"Chiavi attive: {len(configured)}/{len(CONFIG_KEYS)}")
    if configured:
        print("  - " + "\n  - ".join(configured))


# Progress helper (funziona con o senza tqdm)
# ---------------------------------------------------------------------------

class Progress:
    def __init__(self, steps):
        self.steps = steps
        self.total = len(steps)
        self.current = 0
        if HAVE_TQDM:
            self.bar = tqdm(total=self.total, ncols=70, bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}")
        else:
            self.bar = None

    def step(self, label):
        self.current += 1
        if self.bar:
            self.bar.set_description(label[:25])
            self.bar.update(1)
        else:
            filled = int(30 * self.current / self.total)
            bar = "#" * filled + "-" * (30 - filled)
            print(f"\r[{bar}] {self.current}/{self.total} {label[:30]:<30}", end="", flush=True)
            if self.current == self.total:
                print()

    def close(self):
        if self.bar:
            self.bar.close()


def safe(fn, default=None):
    """Esegue fn catturando qualsiasi eccezione, per non bloccare l'intera scansione."""
    try:
        return fn()
    except Exception as e:
        return {"error": str(e)} if default is None else default


# ---------------------------------------------------------------------------
# Moduli di raccolta dati - DOMINI
# ---------------------------------------------------------------------------

def normalize_domain(target):
    if target.startswith("http://") or target.startswith("https://"):
        return urlparse(target).netloc
    return target.strip().lower().rstrip("/")


def run_whois(domain):
    try:
        result = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=15)
        return {"raw": result.stdout.strip()[:4000]}
    except FileNotFoundError:
        return {"error": "comando 'whois' non installato (apk add whois)"}
    except Exception as e:
        return {"error": str(e)}


def run_dns(domain):
    records = {}
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]
    if HAVE_DNSPYTHON:
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=8)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                records[rtype] = []
    else:
        try:
            records["A"] = [socket.gethostbyname(domain)]
        except Exception:
            records["A"] = []
        records["_note"] = "dnspython non installato: solo lookup A base disponibile"
    return records


def check_dns_zone_transfer(domain):
    """Verifica se il DNS del dominio permette un trasferimento di zona (AXFR) - una
    misconfigurazione che rivelerebbe l'intero elenco di sottodomini/record interni
    in un colpo solo. Completamente passivo: è una singola query DNS standard, non
    un 'attacco' - un server configurato correttamente (la normalità oggi) la rifiuta
    semplicemente senza alcun effetto collaterale."""
    if not HAVE_DNSPYTHON:
        return {"error": "dnspython non installato"}
    try:
        ns_answers = dns.resolver.resolve(domain, "NS", lifetime=8)
        nameservers = [str(ns).rstrip(".") for ns in ns_answers]
    except Exception as e:
        return {"error": f"impossibile risolvere i nameserver: {e}"}

    results = {}
    any_vulnerable = False
    for ns in nameservers[:5]:  # tetto per non allungare troppo la scansione
        try:
            ns_ip = socket.gethostbyname(ns)
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10, lifetime=15))
            records = sorted(str(name) for name in zone.nodes.keys())
            results[ns] = {
                "vulnerable": True,
                "records_exposed": len(records),
                "sample_records": records[:20],
            }
            any_vulnerable = True
        except Exception:
            results[ns] = {"vulnerable": False, "note": "trasferimento di zona negato (comportamento corretto)"}

    return {
        "nameservers_checked": nameservers,
        "results": results,
        "any_vulnerable": any_vulnerable,
        "_note": (
            "ATTENZIONE: il DNS espone l'intera lista di sottodomini/record tramite "
            "trasferimento di zona - misconfigurazione seria, oggi rara, da segnalare."
            if any_vulnerable else
            "Nessun nameserver vulnerabile - comportamento corretto/atteso per la stragrande maggioranza dei domini oggi."
        ),
    }


def extract_spf_ips(txt_records):
    """Estrae tutti gli IP menzionati nel record SPF (ip4:/ip6:), non solo l'IP
    principale del dominio - spesso rivela server di invio email aggiuntivi
    (es. altri IP dello stesso hosting/provider usati per la posta)."""
    spf_ips = set()
    includes = set()
    for txt in txt_records:
        if "v=spf1" not in txt:
            continue
        spf_ips.update(re.findall(r"ip4:(\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?)", txt))
        spf_ips.update(re.findall(r"ip6:([0-9a-fA-F:]+(?:/\d+)?)", txt))
        includes.update(re.findall(r"include:(\S+)", txt))
    return {"ips": sorted(spf_ips), "includes": sorted(includes)}


def analyze_spf_ips(txt_records, already_checked_ip=None):
    """Per ogni IP nel record SPF diverso da quello già analizzato come IP principale
    del dominio, esegue IP info + reverse DNS + AbuseIPDB - spesso rivela altra
    infrastruttura collegata (server di invio email dedicati, altri host dello
    stesso provider)."""
    spf_data = extract_spf_ips(txt_records)
    results = {}
    for ip_entry in spf_data["ips"]:
        ip = ip_entry.split("/")[0]  # rimuove eventuale notazione CIDR
        if ip == already_checked_ip:
            results[ip] = {"_note": "coincide con l'IP principale del dominio, già analizzato altrove"}
            continue
        results[ip] = {
            "ip_info": safe(lambda ip=ip: run_ip_info_by_ip(ip)),
            "reverse_dns": safe(lambda ip=ip: run_reverse_dns(ip)),
            "abuseipdb": safe(lambda ip=ip: check_abuseipdb(ip)),
        }
    return {"spf_ips_found": spf_data["ips"], "spf_includes": spf_data["includes"], "additional_ips_analysis": results}


def run_ip_info_by_ip(ip):
    """Come run_ip_info ma parte direttamente da un IP invece che da un dominio da risolvere."""
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,query", timeout=10)
        data = resp.json()
        data["resolved_ip"] = ip
        return data
    except Exception as e:
        return {"error": str(e)}


def run_crtsh(domain):
    """Subdomain discovery via Certificate Transparency logs."""
    try:
        resp = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=20, headers=HEADERS)
        if resp.status_code != 200:
            return {"error": f"crt.sh status {resp.status_code}"}
        data = resp.json()
        names = set()
        for entry in data:
            for n in entry.get("name_value", "").split("\n"):
                n = n.strip().lower()
                if n and "*" not in n:
                    names.add(n)
        return {"subdomains": sorted(names), "count": len(names)}
    except Exception as e:
        return {"error": str(e)}


def run_wayback(domain):
    """Storico Wayback Machine. Le due chiamate sono gestite separatamente: se il
    dominio non ha mai avuto snapshot, l'API di Archive.org a volte risponde con un
    corpo vuoto (non JSON valido) invece di un errore HTTP - senza gestirlo separatamente
    l'intero modulo falliva anche quando una sola delle due chiamate era vuota."""
    result = {"latest_snapshot": {}, "sample_history": [], "has_any_snapshot": False}

    try:
        resp = requests.get(
            f"http://archive.org/wayback/available?url={domain}",
            timeout=15, headers=HEADERS
        )
        if resp.text.strip():  # corpo vuoto = nessuno snapshot, non è un errore
            data = resp.json()
            result["latest_snapshot"] = data.get("archived_snapshots", {}).get("closest", {})
    except Exception as e:
        result["_available_api_error"] = str(e)

    try:
        cdx_resp = requests.get(
            f"http://web.archive.org/cdx/search/cdx?url={domain}&output=json&limit=10&collapse=timestamp:6",
            timeout=15, headers=HEADERS
        )
        if cdx_resp.status_code == 200 and cdx_resp.text.strip():
            cdx_data = cdx_resp.json()
            first_snapshots = cdx_data[1:] if len(cdx_data) > 1 else []
            result["sample_history"] = [row[1] for row in first_snapshots]
    except Exception as e:
        result["_cdx_api_error"] = str(e)

    result["has_any_snapshot"] = bool(result["latest_snapshot"]) or bool(result["sample_history"])
    if not result["has_any_snapshot"] and "_available_api_error" not in result and "_cdx_api_error" not in result:
        result["_note"] = "nessuno snapshot storico trovato per questo dominio - probabilmente mai indicizzato da Archive.org"
    return result


def run_ip_info(domain):
    try:
        ip = socket.gethostbyname(domain)
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,query", timeout=10)
        data = resp.json()
        data["resolved_ip"] = ip
        return data
    except Exception as e:
        return {"error": str(e)}


def run_reverse_ip(ip):
    if not ip:
        return {"error": "nessun IP disponibile"}
    try:
        resp = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=15)
        text = resp.text.strip()
        if "error" in text.lower() or "API count exceeded" in text:
            return {"error": text}
        domains = [d for d in text.split("\n") if d.strip()]
        count = len(domains)
        result = {"co_hosted_domains": domains, "count": count}
        # Flag euristico: molti domini scollegati sullo stesso IP = hosting condiviso,
        # non un'indicazione di collegamento reale tra i siti.
        if count > 15:
            result["_note"] = (
                f"{count} domini sullo stesso IP: numero tipico di hosting condiviso "
                "(shared hosting). La sola co-locazione IP NON indica un collegamento "
                "reale con questi domini - va incrociata con altri segnali (registrant, "
                "nameserver, pattern di contenuto) prima di considerarla significativa."
            )
        elif count > 0:
            result["_note"] = (
                f"Solo {count} domini sullo stesso IP: numero basso, potenzialmente "
                "più significativo di un hosting condiviso di massa - vale la pena "
                "verificare se condividono altri segnali (registrant, nameserver, tema)."
            )
        return result
    except Exception as e:
        return {"error": str(e)}


def run_reverse_dns(ip):
    """Reverse DNS lookup (PTR record) - spesso rivela l'hostname reale del provider."""
    if not ip:
        return {"error": "nessun IP disponibile"}
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        return {"ptr_hostname": hostname, "aliases": aliases}
    except socket.herror as e:
        return {"error": f"nessun record PTR trovato: {e}"}
    except Exception as e:
        return {"error": str(e)}


def check_abuseipdb(ip):
    """Controlla la reputazione dell'IP su AbuseIPDB (richiede API key gratuita,
    tier free: 1000 check/giorno). Si attiva solo se ABUSEIPDB_API_KEY è impostata."""
    api_key = get_api_key("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"skipped": "ABUSEIPDB_API_KEY non impostata (registrazione gratuita su abuseipdb.com)"}
    if not ip:
        return {"error": "nessun IP disponibile"}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=15,
        )
        if resp.status_code != 200:
            return {"error": f"AbuseIPDB status {resp.status_code}"}
        d = resp.json().get("data", {})
        return {
            "abuse_confidence_score": d.get("abuseConfidenceScore"),
            "total_reports": d.get("totalReports"),
            "is_whitelisted": d.get("isWhitelisted"),
            "isp": d.get("isp"),
            "country": d.get("countryCode"),
            "last_reported_at": d.get("lastReportedAt"),
        }
    except Exception as e:
        return {"error": str(e)}


def check_shodan_internetdb(ip):
    """Porte aperte e servizi esposti sull'IP, via Shodan InternetDB - gratuito,
    nessuna chiave richiesta, nessun limite di rate significativo. A differenza
    di nmap, non manda ALCUN pacchetto al target: restituisce solo dati che
    Shodan ha già raccolto nelle sue scansioni periodiche di Internet. Zero
    rumore lato target, resta puro OSINT passivo."""
    if not ip:
        return {"error": "nessun IP disponibile"}
    try:
        resp = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=15)
        if resp.status_code == 404:
            return {"found": False, "_note": "Shodan non ha dati recenti per questo IP"}
        if resp.status_code != 200:
            return {"error": f"Shodan InternetDB status {resp.status_code}"}
        d = resp.json()
        return {
            "found": True,
            "open_ports": d.get("ports", []),
            "hostnames": d.get("hostnames", []),
            "cpes": d.get("cpes", []),  # software/versioni identificate sulle porte aperte
            "known_vulnerabilities": d.get("vulns", []),  # CVE noti se presenti
            "tags": d.get("tags", []),
            "_source": "internetdb.shodan.io (dati passivi, nessuna scansione attiva effettuata da noi)",
        }
    except Exception as e:
        return {"error": str(e)}


def check_censys(ip):
    """Porte/servizi esposti via Censys - come Shodan InternetDB, dati passivi già
    raccolti da loro. Richiede un token API (accounts.censys.io) - dalla metà del 2026
    il tier gratuito non è più sufficiente per queste query, serve un piano a pagamento.
    Si attiva solo se CENSYS_API_TOKEN è impostata."""
    api_token = get_api_key("CENSYS_API_TOKEN")
    if not api_token:
        return {"skipped": "CENSYS_API_TOKEN non impostata (registrazione gratuita su accounts.censys.io/register)"}
    if not ip:
        return {"error": "nessun IP disponibile"}
    try:
        resp = requests.get(
            f"https://search.censys.io/api/v2/hosts/{ip}",
            headers={"Authorization": f"Bearer {api_token}"},
            timeout=20,
        )
        if resp.status_code != 200:
            return {"error": f"Censys status {resp.status_code}"}
        d = resp.json().get("result", {})
        services = d.get("services", [])
        return {
            "found": True,
            "open_ports": [s.get("port") for s in services],
            "services": [{"port": s.get("port"), "protocol": s.get("service_name")} for s in services],
            "location": d.get("location", {}).get("country"),
            "autonomous_system": d.get("autonomous_system", {}).get("name"),
            "_source": "search.censys.io (dati passivi)",
        }
    except Exception as e:
        return {"error": str(e)}


def check_zoomeye(ip):
    """Come Censys/Shodan ma con copertura migliore su infrastrutture asiatiche
    (spesso indicizza host dietro il firewall cinese che Shodan non vede). Richiede
    chiave gratuita (zoomeye.org). Si attiva solo se ZOOMEYE_API_KEY è impostata."""
    api_key = get_api_key("ZOOMEYE_API_KEY")
    if not api_key:
        return {"skipped": "ZOOMEYE_API_KEY non impostata (registrazione gratuita su zoomeye.org)"}
    if not ip:
        return {"error": "nessun IP disponibile"}
    try:
        resp = requests.get(
            "https://api.zoomeye.org/host/search",
            params={"query": f"ip:{ip}"},
            headers={"API-KEY": api_key},
            timeout=20,
        )
        if resp.status_code != 200:
            return {"error": f"ZoomEye status {resp.status_code}"}
        d = resp.json()
        matches = d.get("matches", [])
        return {
            "found": len(matches) > 0,
            "results_count": d.get("total", 0),
            "ports_services": [{"port": m.get("portinfo", {}).get("port"), "service": m.get("portinfo", {}).get("service")} for m in matches[:10]],
            "_source": "zoomeye.org (dati passivi)",
        }
    except Exception as e:
        return {"error": str(e)}


def check_additional_scan_engines(ip):
    """Aggrega i motori aggiuntivi (Censys/ZoomEye) - ognuno si attiva solo se la
    relativa chiave è impostata, altrimenti segnala lo skip senza bloccare nulla.
    Onyphe rimosso dal set (servizio non più utilizzabile per l'account in uso)."""
    return {
        "censys": safe(lambda: check_censys(ip)),
        "zoomeye": safe(lambda: check_zoomeye(ip)),
    }


def query_nvd_by_cpe(cpe, max_results=5):
    """Interroga NVD (database pubblico CVE del NIST/governo USA) per un CPE esatto
    (es. quelli restituiti da Shodan). Nessun contatto col target: pura consultazione
    di un database pubblico di vulnerabilità già note e catalogate."""
    try:
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cpeName": cpe, "resultsPerPage": max_results},
            headers={"User-Agent": "osint-recon/1.0"},
            timeout=20,
        )
        if resp.status_code != 200:
            return {"error": f"NVD status {resp.status_code}"}
        data = resp.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            metrics = cve.get("metrics", {})
            severity = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics:
                    severity = metrics[key][0].get("cvssData", {}).get("baseSeverity") or metrics[key][0].get("baseSeverity")
                    break
            descs = cve.get("descriptions", [])
            desc_en = next((d.get("value") for d in descs if d.get("lang") == "en"), "")
            cves.append({
                "id": cve.get("id"),
                "severity": severity,
                "published": cve.get("published"),
                "description": desc_en[:300],
            })
        return {"cpe": cpe, "cve_count": len(cves), "cves": cves}
    except Exception as e:
        return {"error": str(e), "cpe": cpe}


def query_nvd_by_keyword(keyword, max_results=5):
    """Come query_nvd_by_cpe ma per ricerca testuale (es. 'PHP 7.2.34'), utile quando
    non abbiamo un CPE esatto ma solo una stringa software/versione dagli header HTTP."""
    try:
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": keyword, "resultsPerPage": max_results},
            headers={"User-Agent": "osint-recon/1.0"},
            timeout=20,
        )
        if resp.status_code != 200:
            return {"error": f"NVD status {resp.status_code}"}
        data = resp.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            descs = cve.get("descriptions", [])
            desc_en = next((d.get("value") for d in descs if d.get("lang") == "en"), "")
            cves.append({"id": cve.get("id"), "published": cve.get("published"), "description": desc_en[:300]})
        return {"keyword": keyword, "cve_count": len(cves), "cves": cves}
    except Exception as e:
        return {"error": str(e), "keyword": keyword}


def extract_software_signals(http_fingerprint, shodan_data):
    """Raccoglie le stringhe software/versione da tutto quello che abbiamo già
    raccolto (header HTTP, generator meta, CPE Shodan) per usarle come chiavi di
    ricerca NVD. Generalizzato per qualsiasi stack (PHP, ASP.NET/IIS, CMS vari),
    non solo PHP - così funziona indipendentemente dalla tecnologia del target."""
    signals = []
    seen = set()

    def add(kind, value):
        key = (kind, value.lower())
        if key not in seen:
            seen.add(key)
            signals.append((kind, value))

    if isinstance(shodan_data, dict) and shodan_data.get("cpes"):
        for c in shodan_data["cpes"][:3]:
            add("cpe", c)

    if isinstance(http_fingerprint, dict):
        all_headers = http_fingerprint.get("all_headers", {}) or {}

        # header espliciti "nome/versione" da controllare (copre PHP, ASP.NET/IIS, Java, ecc.)
        headers_to_check = [
            "x-powered-by", "server", "x-aspnet-version", "x-aspnetmvc-version",
        ]
        # alcuni header contengono SOLO il numero di versione, senza nome (es.
        # X-AspNet-Version: 4.0.30319) - qui associamo il nome corretto a mano
        bare_version_header_names = {
            "x-aspnet-version": "ASP.NET",
            "x-aspnetmvc-version": "ASP.NET MVC",
        }
        for hname in headers_to_check:
            val = all_headers.get(hname) or all_headers.get(hname.title()) or (
                http_fingerprint.get("x_powered_by") if hname == "x-powered-by" else
                http_fingerprint.get("server_header") if hname == "server" else None
            )
            if not val:
                continue
            # se l'header contiene solo un numero di versione nudo, associa il nome noto
            if hname in bare_version_header_names and re.fullmatch(r"[\d.]+", val.strip()):
                add("keyword", f"{bare_version_header_names[hname]} {val.strip()}")
                continue
            # pattern generico "Nome/Versione" o "Nome Versione" (es. PHP/7.2.34,
            # Microsoft-IIS/10.0, ASP.NET 4.0.30319, LiteSpeed/6.1)
            for m in re.finditer(r"([A-Za-z][A-Za-z0-9\.\-]{1,30})[/ ]v?([\d]+(?:\.[\d]+){1,3})", val):
                name, version = m.group(1), m.group(2)
                add("keyword", f"{name} {version}")

        # generator meta (rivela CMS/framework e versione, es. "WordPress 6.8.1",
        # "Joomla! 4.2.9", "Drupal 10"). Per i CMS noti costruiamo un CPE preciso
        # (query esatta sul prodotto core) invece di cercare per parola chiave, che
        # su NVD restituisce quasi solo CVE di PLUGIN di terze parti che condividono
        # per puro caso lo stesso numero di versione nel loro changelog - rumore,
        # non segnale reale sul sito analizzato.
        gen = http_fingerprint.get("generator_meta")
        if gen:
            cpe = build_cms_cpe(gen.strip())
            if cpe:
                add("cpe", cpe)
            else:
                add("keyword_cms_core", gen.strip())  # CMS non riconosciuto, ripiego su keyword ma segnalato come meno affidabile

    return signals[:5]  # tetto complessivo per restare nel rate limit NVD (5 richieste/30s senza key)


# Mappatura CMS noti -> vendor:product CPE ufficiale (NVD), per costruire query precise
# invece di ricerche testuali rumorose.
CMS_CPE_TEMPLATES = {
    "wordpress": "cpe:2.3:a:wordpress:wordpress:{version}:*:*:*:*:*:*:*",
    "joomla": "cpe:2.3:a:joomla:joomla\\!:{version}:*:*:*:*:*:*:*",
    "drupal": "cpe:2.3:a:drupal:drupal:{version}:*:*:*:*:*:*:*",
}


def build_cms_cpe(generator_string):
    """Converte una stringa 'generator' (es. 'WordPress 6.8.1') in un CPE preciso
    per il prodotto core, se il CMS è tra quelli noti. Ritorna None se non riconosciuto,
    nel qual caso si ripiega sulla ricerca per parola chiave (meno precisa)."""
    m = re.match(r"([A-Za-z!]+)\D*([\d]+(?:\.[\d]+)*)", generator_string)
    if not m:
        return None
    name, version = m.group(1).lower().rstrip("!"), m.group(2)
    template = CMS_CPE_TEMPLATES.get(name)
    if not template:
        return None
    return template.format(version=version)


def check_known_vulnerabilities(http_fingerprint, shodan_data):
    """Modulo vulnerabilità passivo: incrocia software/versioni già rilevati (header
    HTTP, CPE Shodan) con il database pubblico NVD. Zero contatti col target - è pura
    consultazione di un database governativo di vulnerabilità già catalogate, l'esatto
    equivalente 'senza rumore' di uno scan attivo tipo nmap --script vuln."""
    import time
    signals = extract_software_signals(http_fingerprint, shodan_data)
    if not signals:
        return {"_note": "nessuna stringa software/versione identificabile da header o Shodan per la ricerca CVE"}

    results = []
    for i, (kind, value) in enumerate(signals):
        if i > 0:
            time.sleep(7)  # NVD senza API key: max ~5 richieste/30s, restiamo larghi
        if kind == "cpe":
            results.append(query_nvd_by_cpe(value))
        elif kind == "keyword_cms_core":
            # CMS non riconosciuto per un CPE preciso: ricerca per parola chiave ma
            # scartiamo i risultati che nominano esplicitamente un plugin/tema di terze
            # parti, per ridurre il rumore tipico di questo tipo di ricerca su NVD
            r = query_nvd_by_keyword(value)
            if isinstance(r, dict) and r.get("cves"):
                filtered = [c for c in r["cves"] if "plugin" not in c.get("description", "").lower() and "theme" not in c.get("description", "").lower()]
                r["cves"] = filtered
                r["cve_count"] = len(filtered)
                r["_filter_note"] = "risultati che citavano esplicitamente plugin/temi di terze parti sono stati scartati (rumore tipico della ricerca per parola chiave)"
            results.append(r)
        else:
            results.append(query_nvd_by_keyword(value))

    total_cves = sum(r.get("cve_count", 0) for r in results if isinstance(r, dict))
    return {
        "signals_checked": [v for _, v in signals],
        "total_cves_found": total_cves,
        "details": results,
        "_note": "Fonte: NVD (nvd.nist.gov, database pubblico NIST). Un CVE trovato per la versione software NON conferma che il sito sia effettivamente vulnerabile/non patchato - richiede verifica manuale.",
    }


def run_ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        san = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
        return {
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "san_domains": san,
        }
    except Exception as e:
        return {"error": str(e)}


def run_http_fingerprint(domain):
    result = {}
    for scheme in ("https", "http"):
        try:
            resp = requests.get(f"{scheme}://{domain}", timeout=10, headers=HEADERS, allow_redirects=True)
            result["final_url"] = resp.url
            result["status_code"] = resp.status_code
            result["server_header"] = resp.headers.get("Server")
            result["x_powered_by"] = resp.headers.get("X-Powered-By")
            result["all_headers"] = dict(resp.headers)
            gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', resp.text, re.I)
            result["generator_meta"] = gen.group(1) if gen else None
            result["emails_found"] = extract_emails_clean(resp.text)
            result["social_links_found"] = extract_social_media_links(resp.text)
            result["phones_found"] = extract_phone_numbers(resp.text)
            result["crypto_addresses_found"] = extract_crypto_addresses(resp.text)
            result["company_ids_found"] = extract_company_ids(resp.text)
            result["technologies"] = detect_technologies(resp)
            result["_html_sample"] = resp.text[:200]
            return result
        except Exception as e:
            result[f"{scheme}_error"] = str(e)
    return result


# ---------------------------------------------------------------------------
# Modulo crawl pagine aggiuntive (contatti/chi-siamo/termini) + media
# (reverse image search links + metadati PDF)
# ---------------------------------------------------------------------------

COMMON_ADDITIONAL_PATHS = [
    "/contact", "/contact-us", "/contatti", "/contato", "/contactenos",
    "/about", "/about-us", "/chi-siamo", "/sobre", "/sobre-nos", "/quem-somos",
    "/terms", "/termos", "/termini", "/privacy", "/privacy-policy",
]


def is_junk_email(email):
    """Filtra email che non sono contatti reali: pixel di tracciamento/monitoraggio
    (es. Sentry error-tracking, formato hash a 32 caratteri), placeholder di template
    ('exemplo@meusite.com', 'example@example.com', ecc.)."""
    local = email.split("@")[0].lower()
    domain = email.split("@")[1].lower() if "@" in email else ""
    if re.fullmatch(r"[0-9a-f]{28,36}", local):  # hash tipico di pixel di tracciamento
        return True
    if any(k in domain for k in ("sentry.io", "sentry-next", "wixpress.com", "example.com", "meusite.com")):
        return True
    if local in ("exemplo", "example", "test", "lorem", "dummy", "placeholder"):
        return True
    return False


def extract_emails_clean(text):
    raw = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)
    return sorted(set(e for e in raw if not is_junk_email(e)))


# ---------------------------------------------------------------------------
# Modulo profili social ufficiali (link nel sito) + pivot username completo
# ---------------------------------------------------------------------------

SOCIAL_MEDIA_PATTERNS = {
    "twitter_x": re.compile(r"(?:twitter\.com|x\.com)/(?!intent|share|search|hashtag)([A-Za-z0-9_]{2,30})"),
    "instagram": re.compile(r"instagram\.com/(?!p/|reel/|explore)([A-Za-z0-9_.]{2,30})"),
    "github": re.compile(r"github\.com/(?!orgs/|sponsors)([A-Za-z0-9-]{2,39})"),
    "youtube": re.compile(r"youtube\.com/(?:@|channel/|c/)([A-Za-z0-9_-]{2,30})"),
    "tiktok": re.compile(r"tiktok\.com/@([A-Za-z0-9_.]{2,30})"),
    "linkedin_company": re.compile(r"linkedin\.com/company/([A-Za-z0-9-]{2,60})"),
    "facebook": re.compile(r"facebook\.com/(?!sharer|share)([A-Za-z0-9.]{2,50})"),
}


# Handle noti come boilerplate di piattaforme/librerie, non account reali del sito -
# compaiono spesso nel codice JS/widget di siti costruiti con questi builder (es. Wix
# inserisce riferimenti al proprio account "wix" su GitHub in ogni sito che ospita).
KNOWN_PLATFORM_NOISE = {
    "github": {"wix", "wix-private", "wixplosives", "vercel", "netlify", "squarespace"},
    "twitter_x": {"bolt", "wix", "squarespace", "wordpressdotcom", "shopify"},
}


def extract_social_media_links(text):
    """Estrae gli handle dei profili social ufficiali linkati dal sito (footer/header
    'Seguici su...') - sono dichiarati dal titolare stesso, quindi un punto di partenza
    solido e a bassa ambiguità per un pivot username. Cerca SOLO nell'HTML visibile,
    escludendo gli script (dove i siti costruiti con builder come Wix/Squarespace
    inseriscono riferimenti al proprio codice/librerie, facilmente scambiabili per
    account social del sito)."""
    # rimuove blocchi <script> e <style> prima della ricerca - il codice interno di
    # questi tag non è mai un link cliccabile per l'utente, solo codice/config
    visible_text = re.sub(r"<script\b[^>]*>.*?</script>", "", text, flags=re.DOTALL | re.IGNORECASE)
    visible_text = re.sub(r"<style\b[^>]*>.*?</style>", "", visible_text, flags=re.DOTALL | re.IGNORECASE)

    found = {}
    for platform, pattern in SOCIAL_MEDIA_PATTERNS.items():
        matches = sorted(set(pattern.findall(visible_text)))
        noise = KNOWN_PLATFORM_NOISE.get(platform, set())
        matches = [m for m in matches if m.lower() not in noise]
        if matches:
            found[platform] = matches[:3]
    return found


def run_social_profile_pivot(social_links):
    """Per gli handle social ufficiali trovati sul sito, esegue un pivot username
    COMPLETO (sherlock/socialscan su centinaia di siti + ricerca email/nome da bio) -
    spesso lo stesso username è riusato su altre piattaforme non linkate dal sito,
    rivelando ulteriori profili collegati alla stessa identità."""
    if not social_links:
        return {"_note": "nessun link a profili social ufficiali trovato nel sito"}

    # appiattisce tutti gli handle trovati, dedupe, cap a 2 per non allungare troppo
    # la scansione (ogni pivot username completo può richiedere diversi minuti)
    all_handles = []
    for platform, handles in social_links.items():
        for h in handles:
            if h not in [x[1] for x in all_handles]:
                all_handles.append((platform, h))
    all_handles = all_handles[:2]

    results = {}
    for platform, handle in all_handles:
        footprint = safe(lambda h=handle: run_username_footprint(h))
        contacts = safe(lambda h=handle, fp=footprint: run_contact_discovery(h, fp if isinstance(fp, dict) else {}))
        entry = {
            "found_via_platform": platform,
            "username_footprint": footprint,
            "contact_discovery": contacts,
        }
        if platform == "instagram":
            entry["instagram_toutatis"] = safe(lambda h=handle: run_toutatis(h))
        results[handle] = entry
    return {
        "handles_pivoted": list(results.keys()),
        "results": results,
        "_note": "pivot completo (sherlock/socialscan) eseguito solo sui primi 2 handle trovati, per contenere i tempi",
    }


def crawl_additional_pages(domain, max_pages=5):
    """Va oltre la homepage: prova un piccolo set di pagine tipiche (contatti/chi-siamo/
    termini, anche in IT/PT/EN) e ne estrae email/telefoni/crypto/CNPJ-PIVA, unendoli a
    quanto trovato in home. Molti siti nascondono questi dati fuori dalla pagina principale
    (è il motivo per cui, ad esempio, i CNPJ compaiono spesso solo nel footer di pagine
    'Termini' o 'Chi siamo', non nella home)."""
    found_pages = []
    all_emails, all_phones = set(), set()
    all_crypto = {"bitcoin": set(), "ethereum": set(), "tron": set()}
    all_company_ids = {"cnpj": set(), "piva": set()}
    image_urls, pdf_urls = set(), set()
    all_social = {}

    tried = 0
    for path in COMMON_ADDITIONAL_PATHS:
        if tried >= max_pages:
            break
        for scheme in ("https", "http"):
            try:
                url = f"{scheme}://{domain}{path}"
                resp = requests.get(url, timeout=8, headers=HEADERS, allow_redirects=True)
                if resp.status_code == 200:
                    tried += 1
                    found_pages.append(url)
                    text = resp.text
                    all_emails.update(extract_emails_clean(text))
                    all_phones.update(extract_phone_numbers(text))
                    crypto = extract_crypto_addresses(text)
                    for k in all_crypto:
                        all_crypto[k].update(crypto.get(k, []))
                    cids = extract_company_ids(text)
                    all_company_ids["cnpj"].update(cids.get("cnpj", []))
                    all_company_ids["piva"].update(cids.get("piva", []))
                    for img in re.findall(r'<img[^>]+src=["\']([^"\']+)', text):
                        image_urls.add(urljoin(url, img))
                    for pdf in re.findall(r'href=["\']([^"\']+\.pdf)["\']', text, re.I):
                        pdf_urls.add(urljoin(url, pdf))
                    social = extract_social_media_links(text)
                    for platform, handles in social.items():
                        all_social.setdefault(platform, set()).update(handles)
                    break  # trovata su questo scheme, non serve riprovare l'altro
            except Exception:
                continue

    return {
        "pages_checked": tried,
        "pages_found": found_pages,
        "emails_found": sorted(all_emails),
        "phones_found": sorted(all_phones),
        "crypto_found": {k: sorted(v) for k, v in all_crypto.items() if v},
        "company_ids_found": {k: sorted(v) for k, v in all_company_ids.items() if v},
        "image_urls_found": sorted(image_urls)[:10],
        "pdf_urls_found": sorted(pdf_urls)[:5],
        "social_links_found": {k: sorted(v) for k, v in all_social.items()},
    }


def generate_reverse_image_search_links(image_urls):
    """Prepara i link diretti per la reverse image search sui principali motori.
    Non automatizziamo la ricerca stessa (violerebbe i ToS di questi servizi se fatto
    via script) - i link sono pronti per un tap manuale, puntano direttamente
    all'immagine trovata sul sito."""
    links = []
    for url in image_urls[:5]:
        links.append({
            "image": url,
            "google_lens": f"https://lens.google.com/uploadbyurl?url={url}",
            "yandex": f"https://yandex.com/images/search?rpt=imageview&url={url}",
            "tineye": f"https://tineye.com/search?url={url}",
        })
    return links


def extract_pdf_metadata(pdf_url):
    """Scarica un PDF trovato sul sito ed estrae i metadati (autore, software usato,
    date di creazione/modifica) - spesso rivelano informazioni interne (nome reale
    dell'autore del documento, versione software aziendale) assenti dal resto del
    sito pubblico. Equivalente della funzione principale di FOCA, per iSH."""
    try:
        import pypdf
    except ImportError:
        return {"error": "libreria 'pypdf' non installata (pip install pypdf --break-system-packages)"}
    try:
        resp = requests.get(pdf_url, timeout=15, headers=HEADERS)
        if resp.status_code != 200:
            return {"error": f"status {resp.status_code}", "url": pdf_url}
        from io import BytesIO
        reader = pypdf.PdfReader(BytesIO(resp.content))
        meta = reader.metadata or {}
        return {
            "url": pdf_url,
            "author": meta.get("/Author"),
            "creator": meta.get("/Creator"),
            "producer": meta.get("/Producer"),
            "creation_date": str(meta.get("/CreationDate")) if meta.get("/CreationDate") else None,
            "modification_date": str(meta.get("/ModDate")) if meta.get("/ModDate") else None,
            "page_count": len(reader.pages),
        }
    except Exception as e:
        return {"error": str(e), "url": pdf_url}


def _convert_gps_to_decimal(gps_coord, gps_ref):
    """Converte le coordinate EXIF (formato gradi/minuti/secondi) in decimale."""
    try:
        d, m, s = [float(x.num) / float(x.den) for x in gps_coord.values]
        decimal = d + (m / 60.0) + (s / 3600.0)
        if gps_ref in ("S", "W"):
            decimal = -decimal
        return round(decimal, 6)
    except Exception:
        return None


def extract_image_metadata(image_url):
    """Scarica un'immagine trovata sul sito ed estrae i metadati EXIF (coordinate GPS
    dello scatto, modello fotocamera/telefono, software di editing, data) - spesso
    presenti in foto caricate senza ripulitura, specie da telefono. E' l'altra metà
    dell'equivalente FOCA per iSH (extract_pdf_metadata copre i documenti, questa
    le immagini). Richiede 'exifread', libreria pura Python senza compilazione
    richiesta - installazione leggera anche su iSH."""
    try:
        import exifread
    except ImportError:
        return {"error": "libreria 'exifread' non installata (pip install exifread --break-system-packages)"}
    try:
        resp = requests.get(image_url, timeout=15, headers=HEADERS)
        if resp.status_code != 200:
            return {"error": f"status {resp.status_code}", "url": image_url}
        from io import BytesIO
        tags = exifread.process_file(BytesIO(resp.content), details=False)
        if not tags:
            return {"url": image_url, "has_exif": False, "_note": "nessun metadato EXIF presente (comune per immagini già ripulite da social/CMS)"}

        result = {"url": image_url, "has_exif": True}
        if "Image Make" in tags:
            result["camera_make"] = str(tags["Image Make"])
        if "Image Model" in tags:
            result["camera_model"] = str(tags["Image Model"])
        if "Image Software" in tags:
            result["software"] = str(tags["Image Software"])
        if "EXIF DateTimeOriginal" in tags:
            result["date_taken"] = str(tags["EXIF DateTimeOriginal"])

        lat = tags.get("GPS GPSLatitude")
        lat_ref = str(tags.get("GPS GPSLatitudeRef", ""))
        lon = tags.get("GPS GPSLongitude")
        lon_ref = str(tags.get("GPS GPSLongitudeRef", ""))
        if lat and lon:
            lat_dec = _convert_gps_to_decimal(lat, lat_ref)
            lon_dec = _convert_gps_to_decimal(lon, lon_ref)
            if lat_dec is not None and lon_dec is not None:
                result["gps_latitude"] = lat_dec
                result["gps_longitude"] = lon_dec
                result["gps_maps_link"] = f"https://www.google.com/maps?q={lat_dec},{lon_dec}"

        return result
    except Exception as e:
        return {"error": str(e), "url": image_url}


def run_media_analysis(additional_pages_data):
    """Orchestratore: reverse-image-search links + metadati PDF/immagini, sui
    contenuti trovati durante il crawl delle pagine aggiuntive."""
    image_urls = additional_pages_data.get("image_urls_found", [])
    pdf_urls = additional_pages_data.get("pdf_urls_found", [])
    return {
        "reverse_image_search_links": generate_reverse_image_search_links(image_urls),
        "pdf_metadata": [safe(lambda u=u: extract_pdf_metadata(u)) for u in pdf_urls[:3]],
        "image_metadata": [safe(lambda u=u: extract_image_metadata(u)) for u in image_urls[:5]],
    }


def extract_phone_numbers(text, max_results=5):
    """Estrae numeri di telefono validi dal testo della pagina, usando la libreria
    phonenumbers (molto più affidabile di una regex grezza: valida davvero il numero
    invece di prendere qualsiasi sequenza di cifre). Cerca solo numeri in formato
    internazionale esplicito (con +prefisso) per evitare falsi positivi da altre
    sequenze numeriche presenti nell'HTML/JS della pagina."""
    if not HAVE_PHONENUMBERS:
        return []
    found = set()
    try:
        for match in phonenumbers.PhoneNumberMatcher(text, None):  # None = solo numeri con + esplicito
            if phonenumbers.is_valid_number(match.number):
                found.add(phonenumbers.format_number(match.number, phonenumbers.PhoneNumberFormat.E164))
    except Exception:
        pass
    return sorted(found)[:max_results]


# ---------------------------------------------------------------------------
# Modulo indirizzi crypto (Bitcoin/Ethereum/Tron) - rilevamento + verifica
# passiva su blockchain pubbliche (ledger pubblico per natura, resta OSINT puro)
# ---------------------------------------------------------------------------

CRYPTO_ADDRESS_PATTERNS = {
    "bitcoin": re.compile(r"\b(bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    "ethereum": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "tron": re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b"),
}


def extract_crypto_addresses(text, max_per_chain=3):
    """Estrae indirizzi wallet dal testo della pagina (Bitcoin, Ethereum, Tron/USDT-TRC20
    - quest'ultimo comune nelle truffe di investimento in America Latina). Regex mirate
    per evitare falsi positivi da altre stringhe alfanumeriche presenti nell'HTML."""
    found = {}
    for chain, pattern in CRYPTO_ADDRESS_PATTERNS.items():
        matches = sorted(set(pattern.findall(text)))
        if matches:
            found[chain] = matches[:max_per_chain]
    return found


def check_btc_address(address):
    """Saldo/attività di un indirizzo Bitcoin via Blockstream (API pubblica, no key,
    dati di un ledger pubblico per natura - pura consultazione, zero contatto col target)."""
    try:
        resp = requests.get(f"https://blockstream.info/api/address/{address}", timeout=15, headers=HEADERS)
        if resp.status_code != 200:
            return {"error": f"status {resp.status_code}"}
        d = resp.json()
        funded = d.get("chain_stats", {}).get("funded_txo_sum", 0)
        spent = d.get("chain_stats", {}).get("spent_txo_sum", 0)
        return {
            "tx_count": d.get("chain_stats", {}).get("tx_count", 0),
            "total_received_btc": round(funded / 1e8, 8),
            "current_balance_btc": round((funded - spent) / 1e8, 8),
            "_source": "blockstream.info (dati pubblici della blockchain Bitcoin)",
        }
    except Exception as e:
        return {"error": str(e)}


def check_tron_address(address):
    """Saldo/attività di un indirizzo Tron (spesso usato per USDT-TRC20 nelle truffe
    di investimento) via TronGrid, API pubblica gratuita senza chiave."""
    try:
        resp = requests.get(f"https://api.trongrid.io/v1/accounts/{address}", timeout=15, headers=HEADERS)
        if resp.status_code != 200:
            return {"error": f"status {resp.status_code}"}
        d = resp.json()
        data_list = d.get("data", [])
        if not data_list:
            return {"found": False, "_note": "indirizzo mai attivo sulla blockchain Tron (nessuna transazione)"}
        acc = data_list[0]
        trx_balance = acc.get("balance", 0) / 1e6
        trc20 = acc.get("trc20", [])
        return {
            "found": True,
            "trx_balance": trx_balance,
            "trc20_token_balances_raw": trc20,  # include eventuali saldi USDT-TRC20 (contratto Tether)
            "create_time": acc.get("create_time"),
            "_source": "api.trongrid.io (dati pubblici della blockchain Tron)",
        }
    except Exception as e:
        return {"error": str(e)}


def check_eth_address(address):
    """Saldo/attività di un indirizzo Ethereum via Etherscan - richiede API key gratuita
    (etherscan.io/apis, tier free). Si attiva solo se ETHERSCAN_API_KEY è impostata."""
    api_key = get_api_key("ETHERSCAN_API_KEY")
    if not api_key:
        return {"skipped": "ETHERSCAN_API_KEY non impostata (registrazione gratuita su etherscan.io/apis)"}
    try:
        resp = requests.get(
            "https://api.etherscan.io/api",
            params={"module": "account", "action": "balance", "address": address, "tag": "latest", "apikey": api_key},
            timeout=15,
        )
        d = resp.json()
        if d.get("status") != "1":
            return {"error": d.get("message", "risposta Etherscan non valida")}
        balance_eth = int(d.get("result", 0)) / 1e18
        return {"balance_eth": balance_eth, "_source": "etherscan.io"}
    except Exception as e:
        return {"error": str(e)}


def quick_crypto_pivot(crypto_addresses):
    """Verifica automatica sugli indirizzi crypto trovati nel sito - saldo e attività
    dalla blockchain pubblica corrispondente. Cap basso per numero di indirizzi
    per non allungare troppo la scansione."""
    if not crypto_addresses:
        return {"_note": "nessun indirizzo crypto trovato nella homepage del sito"}
    result = {}
    for addr in crypto_addresses.get("bitcoin", [])[:2]:
        result.setdefault("bitcoin", {})[addr] = safe(lambda a=addr: check_btc_address(a))
    for addr in crypto_addresses.get("tron", [])[:2]:
        result.setdefault("tron", {})[addr] = safe(lambda a=addr: check_tron_address(a))
    for addr in crypto_addresses.get("ethereum", [])[:2]:
        result.setdefault("ethereum", {})[addr] = safe(lambda a=addr: check_eth_address(a))
    return result


# ---------------------------------------------------------------------------
# Modulo estrazione CNPJ/Partita IVA dal sito + verifica registro/sanzioni a cascata
# ---------------------------------------------------------------------------

CNPJ_PATTERN = re.compile(r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b")
# prefissi paese UE più comuni per intercettare Partite IVA nel testo (IT prioritario
# visto il contesto, ma copre anche altri stati membri per riuso futuro dello script)
PIVA_PATTERN = re.compile(
    r"\b(?:IT|DE|FR|ES|NL|BE|PT|AT|PL|SE|DK|FI|IE|GR|CZ|RO|HU|BG|HR|SK|SI|LT|LV|EE|LU|MT|CY)\d{8,12}\b"
)


def extract_company_ids(text):
    """Estrae CNPJ (Brasile) e Partite IVA (Italia/UE) dal testo della pagina -
    tipicamente presenti nei footer dei siti per obbligo di trasparenza legale."""
    cnpj_matches = sorted(set(CNPJ_PATTERN.findall(text)))
    piva_matches = sorted(set(PIVA_PATTERN.findall(text)))
    result = {}
    if cnpj_matches:
        result["cnpj"] = cnpj_matches[:3]
    if piva_matches:
        result["piva"] = piva_matches[:3]
    return result


def quick_company_pivot(company_ids):
    """Verifica automatica COMPLETA sui CNPJ/Partite IVA trovati nel sito: registro
    societario (soci, stato, data apertura) + screening sanzioni sul nome trovato -
    stesso livello di dettaglio di una scansione dedicata di quell'identificativo."""
    if not company_ids:
        return {"_note": "nessun CNPJ o Partita IVA trovato nella homepage del sito"}
    result = {}
    for cnpj in company_ids.get("cnpj", [])[:2]:
        registry = safe(lambda c=cnpj: check_cnpj(c))
        name = registry.get("razao_social") if isinstance(registry, dict) else None
        result.setdefault("cnpj", {})[cnpj] = {
            "registry": registry,
            "sanctions_screening": safe(lambda n=name: check_sanctions(n)) if name else {"_note": "nessuna ragione sociale disponibile"},
        }
    for piva in company_ids.get("piva", [])[:2]:
        registry = safe(lambda p=piva: check_piva(p))
        name = registry.get("name") if isinstance(registry, dict) else None
        result.setdefault("piva", {})[piva] = {
            "registry": registry,
            "sanctions_screening": safe(lambda n=name: check_sanctions(n)) if name else {"_note": "nessuna ragione sociale disponibile"},
        }
    return result


def quick_contact_pivot(emails, phones):
    """Verifica automatica su email/numeri trovati direttamente nel sito scansionato.
    Email: verifica 'leggera' (Gravatar + breach check) per non allungare troppo la
    scansione - per un approfondimento completo (holehe/socialscan) rilanciare osintr
    sulla singola email trovata qui.
    Telefoni: verifica COMPLETA e automatica (analisi numero con tipo/business,
    dorking multi-motore, ricerca Telegram, dark web/leak via IntelligenceX) -
    esattamente come una scansione dedicata di quel numero, fatta in automatico."""
    result = {"emails": {}, "phones": {}}
    for email in (emails or [])[:3]:  # tetto a 3 per non allungare troppo la scansione
        result["emails"][email] = {
            "gravatar": safe(lambda e=email: check_gravatar(e)),
            "breaches": safe(lambda e=email: check_breaches(e)),
        }
    for phone in (phones or [])[:2]:  # tetto a 2 (pipeline completa, più pesante)
        result["phones"][phone] = {
            "analysis": safe(lambda p=phone: analyze_phone(p)),
            "dorking": safe(lambda p=phone: run_dorking(p, "phone")),
            "telegram": safe(lambda p=phone: run_telegram_search(p)),
            "darkweb": safe(lambda p=phone: run_intelx(f'"{p}"')),
        }
    if not emails and not phones:
        return {"_note": "nessuna email o numero di telefono trovato nella homepage del sito"}
    result["_note"] = (
        "email: verifica leggera (Gravatar+breach) - per holehe/socialscan rilanciare osintr sulla singola email. "
        "telefoni: verifica completa automatica (analisi+dorking+Telegram+dark web)."
    )
    return result


# Firme leggere in stile Wappalyzer/BuiltWith (versione gratuita "fatta in casa"):
# non richiede API a pagamento, analizza solo ciò che la richiesta HTTP già restituisce
# (header, cookie, HTML) senza chiamate aggiuntive.
TECH_SIGNATURES = {
    # CMS / e-commerce
    "WordPress": {"html": [r"wp-content/", r"wp-includes/", r'name="generator"[^>]*WordPress']},
    "WooCommerce": {"html": [r"woocommerce"]},
    "Elementor": {"html": [r"elementor"]},
    "Joomla": {"html": [r"/media/jui/", r'name="generator"[^>]*Joomla']},
    "Drupal": {"html": [r"Drupal\.settings", r"/sites/default/files/"], "headers": [("X-Generator", "Drupal")]},
    "Shopify": {"html": [r"cdn\.shopify\.com", r"Shopify\.theme"], "headers": [("X-Shopify-Stage", "")]},
    "Wix": {"html": [r"wix\.com", r"wixstatic\.com"]},
    "Squarespace": {"html": [r"squarespace\.com", r"static1\.squarespace\.com"]},
    "Magento": {"html": [r"Mage\.Cookies", r"/skin/frontend/"]},
    "PrestaShop": {"html": [r"PrestaShop"]},
    # infrastruttura / CDN
    "Cloudflare": {"headers": [("Server", "cloudflare"), ("CF-Ray", "")]},
    "AWS CloudFront": {"headers": [("Via", "CloudFront"), ("X-Amz-Cf-Id", "")]},
    "Nginx": {"headers": [("Server", "nginx")]},
    "Apache": {"headers": [("Server", "Apache")]},
    "Vercel": {"headers": [("Server", "Vercel"), ("X-Vercel-Id", "")]},
    "Netlify": {"headers": [("Server", "Netlify")]},
    # frontend frameworks
    "React": {"html": [r"__REACT_DEVTOOLS", r"data-reactroot", r"react-dom"]},
    "Vue.js": {"html": [r"__vue__", r"vue\.js", r"data-v-[a-f0-9]{8}"]},
    "Angular": {"html": [r"ng-version", r"angular\.js"]},
    "jQuery": {"html": [r"jquery(?:\.min)?\.js"]},
    # analytics / marketing / captcha
    "Google Analytics": {"html": [r"google-analytics\.com/analytics\.js", r"gtag\('config'"]},
    "Google Tag Manager": {"html": [r"googletagmanager\.com/gtm\.js"]},
    "Facebook Pixel": {"html": [r"connect\.facebook\.net.*fbevents\.js"]},
    "Hotjar": {"html": [r"static\.hotjar\.com"]},
    "reCAPTCHA": {"html": [r"google\.com/recaptcha"]},
    "Cloudflare Turnstile": {"html": [r"challenges\.cloudflare\.com/turnstile"]},
    "HubSpot": {"html": [r"js\.hs-scripts\.com", r"hubspot"]},
    "Mailchimp": {"html": [r"chimpstatic\.com"]},
    # pagamenti
    "Stripe": {"html": [r"js\.stripe\.com"]},
    "PayPal": {"html": [r"paypal\.com/sdk/js", r"paypalobjects\.com"]},
}


def detect_technologies(resp):
    found = set()
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    cookies_str = "; ".join(f"{c.name}={c.value}" for c in resp.cookies)
    html = resp.text[:200000]  # limite ragionevole per non rallentare su pagine enormi

    for tech, sig in TECH_SIGNATURES.items():
        matched = False
        for header_name, substring in sig.get("headers", []):
            val = headers_lower.get(header_name.lower())
            if val and (substring == "" or substring.lower() in val.lower()):
                matched = True
                break
        if not matched:
            for pattern in sig.get("html", []):
                if re.search(pattern, html, re.I):
                    matched = True
                    break
        if not matched and "cookie" in sig:
            for substring in sig.get("cookie", []):
                if substring.lower() in cookies_str.lower():
                    matched = True
                    break
        if matched:
            found.add(tech)
    return sorted(found)


def run_robots_sitemap(domain):
    out = {}
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{domain}/robots.txt", timeout=8, headers=HEADERS)
            if r.status_code == 200:
                out["robots_txt"] = r.text[:2000]
                sm = re.findall(r"(?i)sitemap:\s*(\S+)", r.text)
                out["sitemaps_declared"] = sm
            break
        except Exception:
            continue
    return out


# ---------------------------------------------------------------------------
# Modulo domini simili / typosquat (permutazioni + verifica registrazione)
# ---------------------------------------------------------------------------

COMMON_TLDS_FOR_PERMUTATION = ["com", "net", "org", "info", "tech", "online", "site", "xyz", "biz"]
HOMOGLYPH_SUBSTITUTIONS = {"o": "0", "i": "1", "l": "1", "e": "3", "a": "4", "s": "5"}


def generate_domain_permutations(domain, max_permutations=25):
    """Genera varianti plausibili del dominio (typosquat) da verificare: cambio TLD,
    trattini aggiunti/rimossi, omoglifi comuni, parole aggiuntive tipiche (support,
    official, secure, login). Ispirato a dnstwist ma implementato leggero, senza
    dipendenze esterne, per restare compatibile con iSH."""
    parts = domain.rsplit(".", 1)
    if len(parts) != 2:
        return []
    name, original_tld = parts
    candidates = set()

    # variazione TLD
    for tld in COMMON_TLDS_FOR_PERMUTATION:
        if tld != original_tld:
            candidates.add(f"{name}.{tld}")

    # trattini aggiunti/rimossi
    if "-" in name:
        candidates.add(f"{name.replace('-', '')}.{original_tld}")
    else:
        for i in range(1, len(name)):
            candidates.add(f"{name[:i]}-{name[i:]}.{original_tld}")

    # omoglifi comuni (una sostituzione alla volta, per restare plausibili)
    for i, ch in enumerate(name):
        if ch in HOMOGLYPH_SUBSTITUTIONS:
            variant = name[:i] + HOMOGLYPH_SUBSTITUTIONS[ch] + name[i+1:]
            candidates.add(f"{variant}.{original_tld}")

    # parole aggiuntive tipiche delle campagne di phishing/squat
    for suffix in ("-support", "-official", "-secure", "-login", "-app"):
        candidates.add(f"{name}{suffix}.{original_tld}")
        candidates.add(f"{name}{suffix}.com")

    candidates.discard(domain)
    return sorted(candidates)[:max_permutations]


def check_domain_permutations(domain):
    """Genera permutazioni del dominio e verifica quali risultano effettivamente
    registrate (risoluzione DNS). Le permutazioni registrate sono candidati
    concreti per domini 'gemelli'/rete collegata, coerenti con il pattern già
    trovato manualmente in questa indagine (es. kahnawake-gaming-license.com
    vs -cost.com, evotrading.com.br vs .llc)."""
    candidates = generate_domain_permutations(domain)
    registered = []
    for candidate in candidates:
        try:
            ip = socket.gethostbyname(candidate)
            registered.append({"domain": candidate, "resolved_ip": ip})
        except Exception:
            continue  # non registrato o non risolvibile, si scarta silenziosamente
    return {
        "permutations_checked": len(candidates),
        "registered_found": registered,
        "_note": "solo le varianti effettivamente registrate sono elencate - verificare manualmente se sono collegate o coincidenze",
    }


# ---------------------------------------------------------------------------
# Modulo email (holehe)
# ---------------------------------------------------------------------------

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text):
    return ANSI_ESCAPE.sub("", text)


def run_holehe(email):
    """Verifica su quali servizi è registrata l'email, usando holehe (se installato).
    Separa chiaramente i moduli che hanno risposto (trovato/non trovato) dai moduli
    morti/in errore (siti offline, endpoint cambiati, timeout), così il report non
    è affogato nel rumore dei ~121 moduli di cui molti ormai non funzionano più.
    """
    try:
        result = run_subprocess_with_heartbeat(
            ["holehe", email, "--no-color"],
            timeout=240, label="holehe"
        )
        output = strip_ansi(result.stdout)
        found, not_found, broken = [], [], []
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("[+]"):
                found.append(line[3:].strip())
            elif line.startswith("[-]"):
                not_found.append(line[3:].strip())
            elif line.startswith("[x]"):
                broken.append(line[3:].strip())

        total_checked = len(found) + len(not_found) + len(broken)
        return {
            "found_on": found,
            "found_count": len(found),
            "not_found_count": len(not_found),
            "broken_or_offline_modules": broken,
            "broken_count": len(broken),
            "total_modules_checked": total_checked,
            "_summary": (
                f"{len(found)} servizi confermati su {total_checked} moduli totali "
                f"({len(broken)} moduli offline/rotti esclusi dal conteggio utile)."
            ),
        }
    except FileNotFoundError:
        return {"error": "holehe non installato o non nel PATH (pip install holehe --break-system-packages)"}
    except subprocess.TimeoutExpired:
        return {"error": "holehe timeout (240s/4min superati)"}
    except Exception as e:
        return {"error": str(e)}


def check_gravatar(email):
    """Controlla se l'email ha un profilo Gravatar pubblico (API ufficiale, stabile)."""
    import hashlib
    email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
    try:
        resp = requests.get(f"https://www.gravatar.com/{email_hash}.json", headers=HEADERS, timeout=10)
        if resp.status_code == 200:
            profile = resp.json().get("entry", [{}])[0]
            return {
                "found": True,
                "display_name": profile.get("displayName"),
                "profile_url": profile.get("profileUrl"),
                "about_me": profile.get("aboutMe"),
                "accounts_linked": [a.get("url") for a in profile.get("accounts", [])],
            }
        elif resp.status_code == 404:
            return {"found": False}
        else:
            return {"error": f"Gravatar status {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def check_github_email(email):
    """Controlla se l'email è già registrata su GitHub, via endpoint pubblico di validazione
    usato in fase di signup. Tecnica documentata ma non ufficiale: GitHub potrebbe
    modificarla o bloccarla in futuro senza preavviso.
    """
    try:
        resp = requests.get(
            "https://github.com/signup_check/email",
            params={"value": email},
            headers=HEADERS, timeout=10
        )
        text = resp.text.lower()
        if resp.status_code in (200, 422):
            taken = "already" in text or "taken" in text
            return {"likely_registered": taken, "raw_status": resp.status_code, "_note": "tecnica sperimentale, potrebbe rompersi in futuro"}
        return {"error": f"status {resp.status_code}", "_note": "endpoint potrebbe essere cambiato"}
    except Exception as e:
        return {"error": str(e)}


def check_breaches(email):
    """Controlla se l'email è comparsa in violazioni di dati note, via XposedOrNot
    (API pubblica gratuita, senza chiave). Copertura minore rispetto a servizi
    a pagamento come HaveIBeenPwned, ma legittima e senza costi.
    """
    try:
        resp = requests.get(
            f"https://api.xposedornot.com/v1/check-email/{email}",
            headers=HEADERS, timeout=15
        )
        if resp.status_code == 429:
            return {"error": "rate limit XposedOrNot raggiunto, riprova più tardi"}
        if resp.status_code != 200:
            return {"error": f"status {resp.status_code}"}
        data = resp.json()
        breaches = data.get("breaches", [])
        # la risposta a volte è annidata in liste, appiattiamo
        flat = []
        for b in breaches:
            if isinstance(b, list):
                flat.extend(b)
            else:
                flat.append(b)
        return {
            "found_in_breaches": len(flat) > 0,
            "breach_count": len(flat),
            "breach_names": flat,
            "_source": "XposedOrNot (gratuito, copertura parziale rispetto a servizi a pagamento)",
        }
    except Exception as e:
        return {"error": str(e)}


def run_modern_checks(email):
    """Controlli aggiuntivi su servizi non coperti (o coperti male) da holehe."""
    return {
        "gravatar": safe(lambda: check_gravatar(email)),
        "github": safe(lambda: check_github_email(email)),
        "breaches": safe(lambda: check_breaches(email)),
    }


def is_username_target(target):
    """Euristica: nessun punto (i domini quasi sempre ne hanno uno), niente @/cifre pure,
    lunghezza tipica di un handle social."""
    if "." in target or "@" in target:
        return False
    if target.isdigit():
        return False
    return bool(re.match(r"^[a-zA-Z0-9_]{2,32}$", target))


# ---------------------------------------------------------------------------
# Modulo username (footprint su piattaforme social)
# ---------------------------------------------------------------------------

def run_subprocess_with_heartbeat(cmd, timeout, label):
    """Esegue un subprocess mostrando un 'battito' periodico (ogni 15s) mentre è in
    corso - utile per comandi lunghi (sherlock su 400+ siti, holehe su 100+ moduli)
    dove altrimenti il terminale sembra bloccato per minuti senza alcun segnale,
    anche se in realtà sta lavorando normalmente."""
    import threading
    import time

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stop_heartbeat = threading.Event()

    def heartbeat():
        elapsed = 0
        while not stop_heartbeat.wait(15):
            elapsed += 15
            mins = elapsed // 60
            secs = elapsed % 60
            print(f"    ...{label} ancora in corso ({mins}m{secs}s trascorsi, non è bloccato)", flush=True)

    hb_thread = threading.Thread(target=heartbeat, daemon=True)
    hb_thread.start()

    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise
    finally:
        stop_heartbeat.set()


def run_sherlock(username):
    """Usa sherlock (se installato) per un footprint affidabile su centinaia di siti.
    Timeout ampio (10 minuti): una scansione completa su 400+ siti richiede spesso
    5-10 minuti, specialmente da connessione mobile - un timeout troppo corto
    interromperebbe sherlock a metà lavoro senza che il resto dello script se ne accorga.
    Mostra un battito periodico per non sembrare bloccato durante l'attesa."""
    try:
        result = run_subprocess_with_heartbeat(
            ["sherlock", username, "--timeout", "15", "--print-found", "--no-color"],
            timeout=600, label="sherlock"
        )
        output = strip_ansi(result.stdout)
        found = []
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("[+]"):
                found.append(line[3:].strip())
        return {"found_on": found, "found_count": len(found), "raw_output": output[:5000]}
    except FileNotFoundError:
        return None  # non installato, si passa al fallback
    except subprocess.TimeoutExpired:
        return {"error": "sherlock timeout (600s/10min superati) - prova ad aumentare ulteriormente il timeout se la tua connessione è lenta"}
    except Exception as e:
        return {"error": str(e)}


# Fallback leggero se sherlock non è installato: controllo diretto via HTTP status.
# Euristico e meno affidabile di sherlock (alcune piattaforme restituiscono 200
# anche per profili inesistenti, specie se il rendering è via JavaScript).
BASIC_USERNAME_PLATFORMS = {
    "GitHub": "https://github.com/{u}",
    "Reddit": "https://www.reddit.com/user/{u}/about.json",
    "X (Twitter)": "https://x.com/{u}",
    "Instagram": "https://www.instagram.com/{u}/",
    "TikTok": "https://www.tiktok.com/@{u}",
}


def run_basic_username_check(username):
    results = {}
    for platform, url_template in BASIC_USERNAME_PLATFORMS.items():
        url = url_template.format(u=username)
        try:
            resp = requests.get(url, headers=random_headers(), timeout=10, allow_redirects=True)
            results[platform] = {
                "url": url,
                "status_code": resp.status_code,
                "likely_exists": resp.status_code == 200,
            }
        except Exception as e:
            results[platform] = {"url": url, "error": str(e)}
    return {
        "_note": "controllo euristico basato su status HTTP, meno affidabile di sherlock - falsi positivi/negativi possibili",
        "platforms": results,
    }


def run_toutatis(username):
    """Usa Toutatis (se installato) per estrarre email/telefono parzialmente
    mascherati dai metadati pubblici di un account Instagram business, via API
    interna di Instagram. Richiede un session id personale (INSTAGRAM_SESSION_ID)
    ottenuto facendo login su Instagram da browser ed esportando il cookie
    'sessionid' - Instagram può rilevare/bloccare l'uso automatizzato di questo
    cookie, quindi va usato con moderazione per non rischiare il proprio account.
    Endpoint interni non ufficiali: possono rompersi senza preavviso se Instagram
    cambia l'API - stessa fragilità di ogni tool basato su endpoint non documentati."""
    session_id = get_api_key("INSTAGRAM_SESSION_ID")
    if not session_id:
        return {"skipped": "INSTAGRAM_SESSION_ID non impostata (serve il cookie 'sessionid' di un tuo login Instagram - vedi documentazione Toutatis)"}
    try:
        result = subprocess.run(
            ["toutatis", "-u", username, "-s", session_id],
            capture_output=True, text=True, timeout=30
        )
        output = strip_ansi(result.stdout)
        if result.returncode != 0 or not output.strip():
            return {"error": "toutatis non ha restituito risultati (username inesistente, privato, o endpoint Instagram cambiato)", "raw_output": output[:1000]}
        return {"raw_output": output[:2000], "_note": "email/telefono, se presenti nell'output, sono parzialmente mascherati da Instagram stesso (es. 'a***o@gmail.com')"}
    except FileNotFoundError:
        return {"skipped": "toutatis non installato (pip install toutatis --break-system-packages)"}
    except subprocess.TimeoutExpired:
        return {"error": "toutatis timeout (30s superati)"}
    except Exception as e:
        return {"error": str(e)}


def run_socialscan(target):
    """Usa socialscan (se installato) per verificare con precisione se username/email
    sono registrati su una decina di piattaforme (Instagram, Twitter/X, GitHub, Reddit,
    ecc.) - più affidabile del semplice controllo status HTTP perché usa i controlli
    di disponibilità reali di ogni piattaforma (gli stessi usati in fase di registrazione).
    """
    try:
        result = subprocess.run(
            ["socialscan", target],
            capture_output=True, text=True, timeout=90
        )
        output = strip_ansi(result.stdout)
        taken, available, unknown = [], [], []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.lower().startswith(("platform", "-")):
                continue
            if "taken" in line.lower():
                taken.append(line)
            elif "available" in line.lower():
                available.append(line)
            elif line:
                unknown.append(line)
        return {
            "taken_on": taken,
            "available_on": available,
            "unclear_or_errors": unknown,
            "raw_output": output[:3000],
        }
    except FileNotFoundError:
        return None  # non installato
    except subprocess.TimeoutExpired:
        return {"error": "socialscan timeout (90s superati)"}
    except Exception as e:
        return {"error": str(e)}


def run_username_footprint(username):
    sherlock_result = run_sherlock(username)
    socialscan_result = run_socialscan(username)

    if sherlock_result is None and socialscan_result is None:
        fallback = run_basic_username_check(username)
        return {"engine": "fallback_basic", **fallback}

    combined = {}
    if sherlock_result is not None:
        combined["sherlock"] = sherlock_result
    if socialscan_result is not None:
        combined["socialscan"] = socialscan_result
    combined["engine"] = "sherlock+socialscan" if (sherlock_result and socialscan_result) else (
        "sherlock" if sherlock_result else "socialscan"
    )
    return combined


def extract_profile_urls(footprint_result):
    """Estrae gli URL dei profili trovati (da sherlock, socialscan o dal fallback)
    per poterli visitare ed estrarne email/nome eventualmente pubblicati in bio."""
    urls = set()

    sherlock = footprint_result.get("sherlock", {})
    for line in sherlock.get("found_on", []):
        m = re.search(r"https?://\S+", line)
        if m:
            urls.add(m.group(0).rstrip(".,)"))

    socialscan = footprint_result.get("socialscan", {})
    for line in socialscan.get("taken_on", []):
        m = re.search(r"https?://\S+", line)
        if m:
            urls.add(m.group(0).rstrip(".,)"))

    platforms = footprint_result.get("platforms", {})  # fallback_basic
    for info in platforms.values():
        if isinstance(info, dict) and info.get("likely_exists"):
            urls.add(info["url"])

    return list(urls)[:8]  # tetto per non allungare troppo la scansione


def extract_contacts_from_profile(url):
    """Visita una pagina profilo pubblica ed estrae email e possibile nome reale
    (da meta tag og:title/title, o pattern testuali comuni nella bio) - molte
    persone pubblicano queste informazioni volontariamente nel proprio profilo."""
    try:
        resp = requests.get(url, headers=random_headers(), timeout=10)
        if resp.status_code != 200:
            return None
        text = resp.text
        emails = sorted(set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)))
        title_match = re.search(r'<meta property="og:title" content="([^"]+)"', text) or re.search(r"<title>([^<]+)</title>", text)
        possible_name = title_match.group(1).strip() if title_match else None
        if not emails and not possible_name:
            return None
        return {"url": url, "emails_found": emails, "possible_display_name": possible_name}
    except Exception:
        return None


def run_contact_discovery(username, footprint_result):
    """Orchestratore: visita i profili trovati (da qualsiasi motore) ed estrae
    email/nome pubblicati in bio, se presenti."""
    urls = extract_profile_urls(footprint_result)
    results = []
    for url in urls:
        r = safe(lambda u=url: extract_contacts_from_profile(u), default=None)
        if r:
            results.append(r)
    return {
        "profiles_checked": len(urls),
        "contacts_found": results,
        "_note": "email/nomi trovati solo se pubblicati volontariamente in bio dal titolare del profilo - non è una violazione di privacy, sono dati già pubblici sulla pagina stessa",
    }


def scan_username(username, do_analyze):
    steps = ["Footprint social (sherlock/socialscan)", "Ricerca email/nome da profili trovati",
             "Instagram (Toutatis, opzionale)", "Search dorking", "Telegram search", "Dark web/leak (IntelligenceX)"]
    if do_analyze:
        steps.append("Sintesi Gemini")
    prog = Progress(steps)

    data = {"target": username, "type": "username", "scanned_at": datetime.now(timezone.utc).isoformat()}

    prog.step("Footprint social (sherlock/socialscan)")
    data["username_footprint"] = safe(lambda: run_username_footprint(username))

    prog.step("Ricerca email/nome da profili trovati")
    fp = data["username_footprint"] if isinstance(data["username_footprint"], dict) else {}
    data["contact_discovery"] = safe(lambda: run_contact_discovery(username, fp))

    prog.step("Instagram (Toutatis, opzionale)")
    data["instagram_toutatis"] = safe(lambda: run_toutatis(username))

    prog.step("Search dorking")
    data["dorking"] = safe(lambda: run_dorking(username, "username"))

    prog.step("Telegram search")
    data["telegram"] = safe(lambda: run_telegram_search(username))

    prog.step("Dark web/leak (IntelligenceX)")
    data["darkweb"] = safe(lambda: run_intelx(f'"{username}"'))

    if do_analyze:
        prog.step("Sintesi Gemini")
        data["gemini_analysis"] = safe(lambda: gemini_analyze(data, username))

    prog.close()
    return data


# ---------------------------------------------------------------------------
# Modulo registro societario Brasile (CNPJ) - BrasilAPI, gratuita, no key
# ---------------------------------------------------------------------------

def is_cnpj_target(target):
    """CNPJ brasiliano: formato XX.XXX.XXX/XXXX-XX oppure 14 cifre nude."""
    cleaned = re.sub(r"[.\-/]", "", target.strip())
    return bool(re.match(r"^\d{14}$", cleaned))


def check_cnpj(cnpj):
    """Interroga il registro societario brasiliano (Receita Federal) via BrasilAPI -
    gratuita, no key. Restituisce ragione sociale, soci, stato, data apertura, ecc."""
    cleaned = re.sub(r"[.\-/]", "", cnpj.strip())
    try:
        resp = requests.get(f"https://brasilapi.com.br/api/cnpj/v1/{cleaned}", timeout=20, headers=HEADERS)
        if resp.status_code == 404:
            return {"found": False, "_note": "CNPJ non trovato nel registro"}
        if resp.status_code != 200:
            return {"error": f"BrasilAPI status {resp.status_code}"}
        d = resp.json()
        socios = [
            {"nome": s.get("nome_socio"), "qualificacao": s.get("qualificacao_socio"), "data_entrada": s.get("data_entrada_sociedade")}
            for s in d.get("qsa", [])
        ]
        return {
            "found": True,
            "razao_social": d.get("razao_social"),
            "nome_fantasia": d.get("nome_fantasia"),
            "situacao_cadastral": d.get("descricao_situacao_cadastral"),
            "data_situacao_cadastral": d.get("data_situacao_cadastral"),
            "data_inicio_atividade": d.get("data_inicio_atividade"),
            "cnae_principal": d.get("cnae_fiscal_descricao"),
            "capital_social": d.get("capital_social"),
            "endereco": f"{d.get('logradouro','')}, {d.get('municipio','')} - {d.get('uf','')}",
            "socios": socios,
            "_source": "BrasilAPI / Receita Federal (registro pubblico brasiliano)",
        }
    except Exception as e:
        return {"error": str(e)}


def scan_cnpj(cnpj, do_analyze):
    steps = ["Registro societario (CNPJ - Receita Federal)", "Screening sanzioni", "Search dorking", "Dark web/leak (IntelligenceX)"]
    if do_analyze:
        steps.append("Sintesi Gemini")
    prog = Progress(steps)

    data = {"target": cnpj, "type": "cnpj", "scanned_at": datetime.now(timezone.utc).isoformat()}

    prog.step("Registro societario (CNPJ - Receita Federal)")
    data["company_registry"] = safe(lambda: check_cnpj(cnpj))

    prog.step("Screening sanzioni")
    company_name = data["company_registry"].get("razao_social") if isinstance(data["company_registry"], dict) else None
    data["sanctions_screening"] = safe(lambda: check_sanctions(company_name)) if company_name else {"_note": "nessuna ragione sociale disponibile per lo screening"}

    prog.step("Search dorking")
    query_term = data["company_registry"].get("razao_social") if isinstance(data["company_registry"], dict) and data["company_registry"].get("razao_social") else cnpj
    data["dorking"] = safe(lambda: run_dorking(query_term, "email"))  # riusa il set di query generico

    prog.step("Dark web/leak (IntelligenceX)")
    data["darkweb"] = safe(lambda: run_intelx(f'"{cnpj}"'))

    if do_analyze:
        prog.step("Sintesi Gemini")
        data["gemini_analysis"] = safe(lambda: gemini_analyze(data, cnpj))

    prog.close()
    return data


# ---------------------------------------------------------------------------
# Modulo registro societario Italia/UE (Partita IVA) - VIES, gratuita, no key
# ---------------------------------------------------------------------------

def is_piva_target(target):
    """Partita IVA italiana/UE: prefisso paese (2 lettere) + 8-12 cifre, es. IT02117980405."""
    cleaned = target.strip().upper().replace(" ", "")
    return bool(re.match(r"^[A-Z]{2}\d{8,12}$", cleaned))


def check_piva(piva):
    """Valida una Partita IVA tramite il servizio ufficiale VIES della Commissione
    Europea - gratuito, no key. Restituisce validità, ragione sociale e indirizzo
    se disponibili (dipende dallo stato membro, alcuni non espongono questi dati)."""
    cleaned = piva.strip().upper().replace(" ", "")
    country_code, vat_number = cleaned[:2], cleaned[2:]
    try:
        resp = requests.get(
            f"https://ec.europa.eu/taxation_customs/vies/rest-api/ms/{country_code}/vat/{vat_number}",
            timeout=20, headers=HEADERS
        )
        if resp.status_code != 200:
            return {"error": f"VIES status {resp.status_code}"}
        d = resp.json()
        return {
            "valid": d.get("isValid"),
            "country_code": d.get("countryCode"),
            "vat_number": d.get("vatNumber"),
            "name": d.get("name"),
            "address": d.get("address"),
            "request_date": d.get("requestDate"),
            "_source": "VIES (servizio ufficiale Commissione Europea)",
            "_note": "alcuni stati membri non espongono nome/indirizzo tramite VIES anche per partite IVA valide",
        }
    except Exception as e:
        return {"error": str(e)}


def scan_piva(piva, do_analyze):
    steps = ["Registro societario (Partita IVA - VIES)", "Screening sanzioni", "Search dorking", "Dark web/leak (IntelligenceX)"]
    if do_analyze:
        steps.append("Sintesi Gemini")
    prog = Progress(steps)

    data = {"target": piva, "type": "piva", "scanned_at": datetime.now(timezone.utc).isoformat()}

    prog.step("Registro societario (Partita IVA - VIES)")
    data["company_registry"] = safe(lambda: check_piva(piva))

    prog.step("Screening sanzioni")
    company_name = data["company_registry"].get("name") if isinstance(data["company_registry"], dict) else None
    data["sanctions_screening"] = safe(lambda: check_sanctions(company_name)) if company_name else {"_note": "nessuna ragione sociale disponibile per lo screening"}

    prog.step("Search dorking")
    query_term = data["company_registry"].get("name") if isinstance(data["company_registry"], dict) and data["company_registry"].get("name") else piva
    data["dorking"] = safe(lambda: run_dorking(query_term, "email"))

    prog.step("Dark web/leak (IntelligenceX)")
    data["darkweb"] = safe(lambda: run_intelx(f'"{piva}"'))

    if do_analyze:
        prog.step("Sintesi Gemini")
        data["gemini_analysis"] = safe(lambda: gemini_analyze(data, piva))

    prog.close()
    return data


# ---------------------------------------------------------------------------
# Modulo screening sanzioni (Consolidated Screening List - governo USA)
# ---------------------------------------------------------------------------

def check_sanctions(name):
    """Controlla un nome (persona o azienda) contro le liste di sanzioni consolidate
    USA (OFAC/SDN e altre) via l'API pubblica trade.gov. Richiede una API key gratuita
    (registrazione su api.data.gov/signup). Si attiva solo se TRADE_GOV_API_KEY è impostata."""
    api_key = get_api_key("TRADE_GOV_API_KEY")
    if not api_key:
        return {"skipped": "TRADE_GOV_API_KEY non impostata (registrazione gratuita su api.data.gov/signup)"}
    if not name:
        return {"error": "nessun nome fornito per lo screening"}
    try:
        resp = requests.get(
            "https://api.trade.gov/consolidated_screening_list/search",
            params={"q": name, "api_key": api_key},
            timeout=20,
        )
        if resp.status_code != 200:
            return {"error": f"trade.gov status {resp.status_code}"}
        d = resp.json()
        results = d.get("results", [])
        matches = [
            {
                "name": r.get("name"),
                "source": r.get("source"),  # es. "SDN" (OFAC), "Denied Persons List", ecc.
                "programs": r.get("programs"),
                "type": r.get("type"),
                "countries": r.get("countries"),
            }
            for r in results[:10]
        ]
        return {
            "query": name,
            "match_count": len(matches),
            "matches": matches,
            "_source": "Consolidated Screening List (trade.gov, dati ufficiali governo USA - OFAC/SDN e altre liste)",
            "_note": "una corrispondenza per nome non è automaticamente conferma di identità - nomi comuni possono generare falsi positivi, verificare sempre i dettagli",
        }
    except Exception as e:
        return {"error": str(e)}


def is_email_target(target):
    return bool(re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target.strip()))


# ---------------------------------------------------------------------------
# Modulo search engine dorking + Telegram (via DuckDuckGo HTML, no API key)
# ---------------------------------------------------------------------------

def web_search_engine(query, max_results=5, max_retries=2):
    """Ricerca web multi-motore: prova DuckDuckGo (endpoint HTML principale, poi lite
    come fallback), e infine Bing se anche DuckDuckGo è bloccato su entrambi gli
    endpoint. Applica rotazione User-Agent e backoff esponenziale su 429/202."""
    import time

    def parse_ddg_html_results(html):
        matches = re.findall(
            r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
            html, re.DOTALL
        )
        results = []
        for url, title in matches[:max_results]:
            clean_title = re.sub(r"<[^>]+>", "", title).strip()
            results.append({"title": clean_title, "url": url})
        return results

    def parse_ddg_lite_results(html):
        # lite.duckduckgo.com usa markup più semplice, i link risultato hanno class="result-link"
        matches = re.findall(r'class="result-link"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', html, re.DOTALL)
        results = []
        for url, title in matches[:max_results]:
            clean_title = re.sub(r"<[^>]+>", "", title).strip()
            results.append({"title": clean_title, "url": url})
        return results

    def parse_bing_results(html):
        matches = re.findall(
            r'<li class="b_algo"[^>]*>.*?<h2[^>]*><a href="([^"]+)"[^>]*>(.*?)</a>',
            html, re.DOTALL
        )
        results = []
        for url, title in matches[:max_results]:
            clean_title = re.sub(r"<[^>]+>", "", title).strip()
            results.append({"title": clean_title, "url": url})
        return results

    last_error = None

    # Tentativo 1: DuckDuckGo endpoint HTML principale, con retry/backoff
    for attempt in range(max_retries + 1):
        try:
            resp = requests.post(
                "https://html.duckduckgo.com/html/",
                data={"q": query},
                headers=random_headers(),
                timeout=15,
            )
            if resp.status_code == 200:
                results = parse_ddg_html_results(resp.text)
                return {"query": query, "results": results, "count": len(results), "_source": "html.duckduckgo.com"}

            last_error = f"DuckDuckGo (html) status {resp.status_code}"
            if resp.status_code in (429, 202) and attempt < max_retries:
                time.sleep(2 ** (attempt + 1))  # backoff esponenziale: 2s, 4s, ...
                continue
            break
        except Exception as e:
            last_error = str(e)
            if attempt < max_retries:
                time.sleep(2 ** (attempt + 1))
                continue
            break

    # Tentativo 2: DuckDuckGo endpoint lite, spesso meno soggetto a blocchi anti-bot
    try:
        resp = requests.get(
            "https://lite.duckduckgo.com/lite/",
            params={"q": query},
            headers=random_headers(),
            timeout=15,
        )
        if resp.status_code == 200:
            results = parse_ddg_lite_results(resp.text)
            return {"query": query, "results": results, "count": len(results), "_source": "lite.duckduckgo.com (fallback)"}
        last_error = f"{last_error} | DuckDuckGo (lite) status {resp.status_code}"
    except Exception as e:
        last_error = f"{last_error} | lite fallback: {str(e)}"

    # Tentativo 3: Bing, motore diverso - utile proprio quando DuckDuckGo blocca
    # sistematicamente (i due motori raramente sono bloccati insieme nello stesso momento)
    try:
        resp = requests.get(
            "https://www.bing.com/search",
            params={"q": query},
            headers=random_headers(),
            timeout=15,
        )
        if resp.status_code == 200:
            results = parse_bing_results(resp.text)
            return {"query": query, "results": results, "count": len(results), "_source": "bing.com (fallback)"}
        last_error = f"{last_error} | Bing status {resp.status_code}"
    except Exception as e:
        last_error = f"{last_error} | Bing fallback: {str(e)}"

    return {"error": last_error, "query": query}


# alias per compatibilità con il resto del codice/con eventuali script esterni
duckduckgo_search = web_search_engine


def build_dork_queries(target, target_type):
    if target_type == "domain":
        return [
            f"site:{target}",
            f"site:{target} filetype:pdf",
            f"site:{target} filetype:xls OR filetype:xlsx OR filetype:doc OR filetype:docx",
            f"site:{target} inurl:admin OR inurl:login",
            f'"{target}" -site:{target}',
        ]
    elif target_type == "email":
        return [
            f'"{target}"',
            f'"{target}" leak OR breach OR pastebin',
            f'"{target}" filetype:pdf OR filetype:xls OR filetype:xlsx',
        ]
    elif target_type == "phone":
        return [
            f'"{target}"',
            f'"{target}" leak OR pastebin OR breach',
        ]
    elif target_type == "username":
        return [
            f'"{target}"',
            f'"{target}" site:github.com OR site:reddit.com OR site:x.com',
            f'"{target}" leak OR pastebin OR breach',
        ]
    return [f'"{target}"']


def run_dorking(target, target_type):
    queries = build_dork_queries(target, target_type)
    output = {}
    for q in queries:
        output[q] = duckduckgo_search(q, max_results=5)
    return output


def run_telegram_search(target):
    """Cerca canali/gruppi Telegram pubblici che menzionano il target, via DDG (site:t.me)."""
    result = duckduckgo_search(f'site:t.me "{target}"', max_results=8)
    # tentativo aggiuntivo: se il target è un dominio/username senza spazi, controlla
    # anche se esiste una pagina pubblica diretta t.me/<target senza TLD/@>
    candidate = re.sub(r"^https?://", "", target).split(".")[0].lstrip("@").strip()
    direct_check = {}
    if candidate and re.match(r"^[a-zA-Z0-9_]{3,32}$", candidate):
        try:
            r = requests.get(f"https://t.me/{candidate}", headers=HEADERS, timeout=10)
            exists = "tgme_page_title" in r.text or r.status_code == 200 and "og:title" in r.text
            direct_check = {
                "checked_handle": candidate,
                "url": f"https://t.me/{candidate}",
                "page_found": exists,
                "_note": "verifica euristica sulla pagina pubblica di preview, non conferma univoca",
            }
            if exists:
                # estrae nome canale, descrizione e conteggio membri/iscritti dalla
                # pagina di preview pubblica (dati mostrati da Telegram stesso, no login)
                title = re.search(r'<meta property="og:title" content="([^"]+)"', r.text)
                desc = re.search(r'<meta property="og:description" content="([^"]+)"', r.text)
                img = re.search(r'<meta property="og:image" content="([^"]+)"', r.text)
                members = re.search(r'(\d[\d,\.]*)\s*(?:members|subscribers|iscritti|membri)', r.text, re.I)
                direct_check["channel_title"] = title.group(1) if title else None
                direct_check["channel_description"] = desc.group(1) if desc else None
                direct_check["has_profile_image"] = bool(img)
                direct_check["members_hint"] = members.group(1) if members else None
        except Exception as e:
            direct_check = {"error": str(e)}
    return {"search_results": result, "direct_handle_check": direct_check}


# ---------------------------------------------------------------------------
# Modulo Dark Web / Leak (IntelligenceX - richiede API key gratuita)
# NOTA: DarkSearch.io ha chiuso l'accesso pubblico alla sua API nel 2026,
# quindi è stato sostituito con IntelligenceX (intelx.io), che copre dark web,
# leak e snapshot storici senza bisogno di Tor lato client.
# ---------------------------------------------------------------------------

def run_intelx(query):
    """Cerca il target su IntelligenceX (dark web, leak, snapshot storici).
    Richiede una API key gratuita: registrazione su intelx.io/signup, poi
    la chiave si trova in intelx.io/account?tab=developer.
    Si attiva solo se INTELX_API_KEY è impostata."""
    api_key = get_api_key("INTELX_API_KEY")
    if not api_key:
        return {"skipped": "INTELX_API_KEY non impostata (registrazione gratuita su intelx.io/signup)"}
    try:
        # avvia la ricerca
        search_resp = requests.post(
            "https://free.intelx.io/intelligent/search",
            json={"term": query, "maxresults": 10, "media": 0, "sort": 2},
            headers={"x-key": api_key, "User-Agent": "osint-recon/1.0"},
            timeout=20,
        )
        if search_resp.status_code != 200:
            return {"error": f"IntelligenceX status {search_resp.status_code}"}
        search_id = search_resp.json().get("id")
        if not search_id:
            return {"error": "IntelligenceX non ha restituito un id di ricerca valido"}

        # recupera i risultati (la ricerca è asincrona lato loro)
        results_resp = requests.get(
            f"https://free.intelx.io/intelligent/search/result",
            params={"id": search_id, "limit": 10},
            headers={"x-key": api_key, "User-Agent": "osint-recon/1.0"},
            timeout=20,
        )
        if results_resp.status_code != 200:
            return {"error": f"IntelligenceX risultati status {results_resp.status_code}"}
        records = results_resp.json().get("records", [])
        results = [
            {
                "name": r.get("name"),
                "date": r.get("date"),
                "bucket": r.get("bucket"),  # es. "leaks.public", "darknet.tor", ecc.
                "media_type": r.get("media"),
            }
            for r in records
        ]
        return {
            "query": query,
            "count": len(results),
            "results": results,
            "_note": "Copertura parziale (tier gratuito limitato) - assenza di risultati non è una garanzia.",
        }
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Modulo numeri di telefono
# ---------------------------------------------------------------------------

PHONE_TYPE_LABELS = {
    0: "Fisso (linea fissa)",
    1: "Mobile",
    2: "Fisso o mobile (ambiguo)",
    3: "Numero verde (toll-free)",
    4: "Tariffa premium (a pagamento maggiorato)",
    5: "Tariffa condivisa",
    6: "VoIP (voce su internet - es. Skype, servizi VoIP)",
    7: "Segreteria telefonica personale",
    8: "Cercapersone",
    9: "UAN (numero aziendale univoco - tipico di call center/business)",
    10: "Numero personale (servizio di reindirizzamento personale)",
    27: "Non classificabile",
    99: "Sconosciuto",
}

# tipi che indicano tipicamente un uso "business"/organizzativo piuttosto che un privato
BUSINESS_LIKE_TYPES = {3, 4, 5, 6, 9}


def analyze_phone(number):
    if not HAVE_PHONENUMBERS:
        return {"error": "libreria 'phonenumbers' non installata (pip install phonenumbers)"}
    try:
        parsed = phonenumbers.parse(number, None)
        type_code = phonenumbers.number_type(parsed)
        return {
            "valid": phonenumbers.is_valid_number(parsed),
            "possible": phonenumbers.is_possible_number(parsed),
            "country_code": parsed.country_code,
            "national_number": parsed.national_number,
            "region": geocoder.description_for_number(parsed, "it"),
            "carrier": carrier.name_for_number(parsed, "it"),
            "line_type_code": int(type_code),
            "line_type": PHONE_TYPE_LABELS.get(int(type_code), f"Codice sconosciuto ({type_code})"),
            "likely_business_number": int(type_code) in BUSINESS_LIKE_TYPES,
            "timezones": pn_timezone.time_zones_for_number(parsed),
            "e164_format": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
            "international_format": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        }
    except Exception as e:
        return {"error": str(e)}


def is_phone_target(target):
    cleaned = re.sub(r"[\s\-().]", "", target)
    return bool(re.match(r"^\+?\d{6,15}$", cleaned))


# ---------------------------------------------------------------------------
# Sintesi con Gemini (Google AI Studio)
# ---------------------------------------------------------------------------

def gemini_analyze(data, target):
    api_key = get_api_key("GOOGLE_API_KEY")
    if not api_key:
        return {"error": "GOOGLE_API_KEY non impostata. Esegui: export GOOGLE_API_KEY='...'"}

    prompt = f"""Sei un analista OSINT. Analizza questi dati raccolti su "{target}" e produci un report strutturato in italiano, diviso ESATTAMENTE in tre sezioni:

1. FATTI VERIFICATI - solo dati oggettivi presenti nei risultati (date, IP, record DNS, ecc.)
2. COLLEGAMENTI PROBABILI - correlazioni plausibili tra i dati (es. stesso IP/hosting di altri domini, pattern temporali, stesso registrant)
3. OSSERVAZIONI ANALITICHE - ipotesi che richiedono valutazione umana, red flags o punti da approfondire

Sii conciso, evidenzia solo ciò che è rilevante. Non inventare nulla che non sia supportato dai dati.
Attenzione: se il campo reverse_ip contiene molti domini scollegati (hosting condiviso), NON trattarlo come un collegamento reale - segui la nota "_note" già presente nei dati.
Attenzione: il controllo breach data usa una fonte gratuita con copertura parziale - un risultato "non trovato" NON significa che l'email sia sicuramente pulita, solo che non è nel dataset di questa fonte specifica.

DATI RACCOLTI:
{json.dumps(data, indent=2, ensure_ascii=False, default=str)[:15000]}
"""

    # Modelli in ordine di preferenza: se il primo è sovraccarico (503) o ha esaurito
    # la quota (429), si prova automaticamente il successivo.
    fallback_models = ["gemini-3.6-flash", "gemini-2.5-flash", "gemini-3.5-flash-lite"]
    attempts = []

    for model in fallback_models:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
            resp = requests.post(
                url,
                json={"contents": [{"parts": [{"text": prompt}]}]},
                timeout=60,
            )
            if resp.status_code == 200:
                result = resp.json()
                text = result["candidates"][0]["content"]["parts"][0]["text"]
                return {"analysis": text, "model_used": model, "attempts": attempts}

            attempts.append(f"{model}: status {resp.status_code}")
            if resp.status_code in (503, 429):
                continue  # modello sovraccarico/quota esaurita, prova il prossimo
            else:
                # errore diverso (es. 404 modello inesistente, 400 richiesta malformata):
                # non ha senso riprovare gli altri modelli con lo stesso identico problema
                # solo se l'errore è specifico di questo modello, altrimenti continua comunque
                continue
        except Exception as e:
            attempts.append(f"{model}: {str(e)}")
            continue

    return {"error": f"Tutti i modelli Gemini hanno fallito. Dettagli: {'; '.join(attempts)}"}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def scan_domain(domain, do_analyze):
    domain = normalize_domain(domain)
    steps = [
        "WHOIS", "DNS records", "DNS zone transfer (AXFR)", "Subdomain (crt.sh)", "Wayback history",
        "IP info", "Reverse DNS (PTR)", "Reverse IP", "AbuseIPDB",
        "Porte esposte (Shodan InternetDB)", "Motori aggiuntivi (Censys/ZoomEye)", "SPF - IP aggiuntivi",
        "SSL certificate", "HTTP fingerprint", "Vulnerabilità note (NVD)",
        "Crawl pagine aggiuntive + media",
        "Verifica contatti trovati nel sito", "Verifica indirizzi crypto trovati nel sito",
        "Verifica CNPJ/P.IVA trovati nel sito",
        "Profili social ufficiali + pivot username",
        "Domini simili/typosquat", "Robots/Sitemap",
        "Search dorking", "Telegram search", "Dark web/leak (IntelligenceX)",
    ]
    if do_analyze:
        steps.append("Sintesi Gemini")

    prog = Progress(steps)
    data = {"target": domain, "type": "domain", "scanned_at": datetime.now(timezone.utc).isoformat()}

    prog.step("WHOIS")
    data["whois"] = safe(lambda: run_whois(domain))

    prog.step("DNS records")
    data["dns"] = safe(lambda: run_dns(domain))

    prog.step("DNS zone transfer (AXFR)")
    data["dns_zone_transfer"] = safe(lambda: check_dns_zone_transfer(domain))

    prog.step("Subdomain (crt.sh)")
    data["subdomains"] = safe(lambda: run_crtsh(domain))

    prog.step("Wayback history")
    data["wayback"] = safe(lambda: run_wayback(domain))

    prog.step("IP info")
    data["ip_info"] = safe(lambda: run_ip_info(domain))

    prog.step("Reverse DNS (PTR)")
    resolved_ip = data["ip_info"].get("resolved_ip") if isinstance(data["ip_info"], dict) else None
    data["reverse_dns"] = safe(lambda: run_reverse_dns(resolved_ip))

    prog.step("Reverse IP")
    data["reverse_ip"] = safe(lambda: run_reverse_ip(resolved_ip))

    prog.step("AbuseIPDB")
    data["abuseipdb"] = safe(lambda: check_abuseipdb(resolved_ip))

    prog.step("Porte esposte (Shodan InternetDB)")
    data["exposed_ports"] = safe(lambda: check_shodan_internetdb(resolved_ip))

    prog.step("Motori aggiuntivi (Censys/ZoomEye)")
    data["additional_scan_engines"] = safe(lambda: check_additional_scan_engines(resolved_ip))

    prog.step("SPF - IP aggiuntivi")
    txt_records = data["dns"].get("TXT", []) if isinstance(data["dns"], dict) else []
    data["spf_analysis"] = safe(lambda: analyze_spf_ips(txt_records, resolved_ip))

    prog.step("SSL certificate")
    data["ssl"] = safe(lambda: run_ssl_info(domain))

    prog.step("HTTP fingerprint")
    data["http_fingerprint"] = safe(lambda: run_http_fingerprint(domain))

    prog.step("Vulnerabilità note (NVD)")
    data["known_vulnerabilities"] = safe(lambda: check_known_vulnerabilities(data["http_fingerprint"], data["exposed_ports"]))

    prog.step("Crawl pagine aggiuntive + media")
    data["additional_pages"] = safe(lambda: crawl_additional_pages(domain))
    data["media_analysis"] = safe(lambda: run_media_analysis(data["additional_pages"] if isinstance(data["additional_pages"], dict) else {}))

    # unisce quanto trovato in homepage con quanto trovato nelle pagine aggiuntive,
    # cosi' i pivot successivi (contatti/crypto/company) vedono tutto, non solo la home
    hf = data["http_fingerprint"] if isinstance(data["http_fingerprint"], dict) else {}
    ap = data["additional_pages"] if isinstance(data["additional_pages"], dict) else {}
    merged_emails = sorted(set(hf.get("emails_found", [])) | set(ap.get("emails_found", [])))
    merged_phones = sorted(set(hf.get("phones_found", [])) | set(ap.get("phones_found", [])))
    merged_crypto = {}
    for k in ("bitcoin", "ethereum", "tron"):
        vals = set(hf.get("crypto_addresses_found", {}).get(k, [])) | set(ap.get("crypto_found", {}).get(k, []))
        if vals:
            merged_crypto[k] = sorted(vals)
    merged_company_ids = {}
    for k in ("cnpj", "piva"):
        vals = set(hf.get("company_ids_found", {}).get(k, [])) | set(ap.get("company_ids_found", {}).get(k, []))
        if vals:
            merged_company_ids[k] = sorted(vals)

    prog.step("Verifica contatti trovati nel sito")
    data["discovered_contacts_analysis"] = safe(
        lambda: quick_contact_pivot(merged_emails, merged_phones)
    )

    prog.step("Verifica indirizzi crypto trovati nel sito")
    data["discovered_crypto_analysis"] = safe(
        lambda: quick_crypto_pivot(merged_crypto)
    )

    prog.step("Verifica CNPJ/P.IVA trovati nel sito")
    data["discovered_company_analysis"] = safe(
        lambda: quick_company_pivot(merged_company_ids)
    )

    prog.step("Profili social ufficiali + pivot username")
    merged_social = {}
    for src in (hf.get("social_links_found", {}), ap.get("social_links_found", {})):
        for platform, handles in src.items():
            merged_social.setdefault(platform, set()).update(handles)
    merged_social = {k: sorted(v) for k, v in merged_social.items()}
    data["social_profiles_found"] = merged_social
    data["social_profile_pivot"] = safe(lambda: run_social_profile_pivot(merged_social))

    prog.step("Domini simili/typosquat")
    data["similar_domains"] = safe(lambda: check_domain_permutations(domain))

    prog.step("Robots/Sitemap")
    data["robots_sitemap"] = safe(lambda: run_robots_sitemap(domain))

    prog.step("Search dorking")
    data["dorking"] = safe(lambda: run_dorking(domain, "domain"))

    prog.step("Telegram search")
    data["telegram"] = safe(lambda: run_telegram_search(domain))

    prog.step("Dark web/leak (IntelligenceX)")
    data["darkweb"] = safe(lambda: run_intelx(domain))

    if do_analyze:
        prog.step("Sintesi Gemini")
        data["gemini_analysis"] = safe(lambda: gemini_analyze(data, domain))

    prog.close()
    return data


def scan_phone(number, do_analyze):
    steps = ["Analisi numero", "Search dorking", "Telegram search", "Dark web/leak (IntelligenceX)"]
    if do_analyze:
        steps.append("Sintesi Gemini")
    prog = Progress(steps)

    data = {"target": number, "type": "phone", "scanned_at": datetime.now(timezone.utc).isoformat()}
    prog.step("Analisi numero")
    data["phone_analysis"] = safe(lambda: analyze_phone(number))

    prog.step("Search dorking")
    data["dorking"] = safe(lambda: run_dorking(number, "phone"))

    prog.step("Telegram search")
    data["telegram"] = safe(lambda: run_telegram_search(number))

    prog.step("Dark web/leak (IntelligenceX)")
    data["darkweb"] = safe(lambda: run_intelx(f'"{number}"'))

    if do_analyze:
        prog.step("Sintesi Gemini")
        data["gemini_analysis"] = safe(lambda: gemini_analyze(data, number))

    prog.close()
    return data


def scan_email(email, do_analyze):
    email = email.strip().lower()
    steps = [
        "Holehe (email check)", "Socialscan", "Controlli moderni (Gravatar/GitHub)",
        "Search dorking", "Telegram search", "Dark web/leak (IntelligenceX)",
    ]
    if do_analyze:
        steps.append("Sintesi Gemini")
    prog = Progress(steps)

    data = {"target": email, "type": "email", "scanned_at": datetime.now(timezone.utc).isoformat()}

    prog.step("Holehe (email check)")
    data["holehe"] = safe(lambda: run_holehe(email))

    prog.step("Socialscan")
    socialscan_res = safe(lambda: run_socialscan(email), default={"skipped": "socialscan non installato"})
    data["socialscan"] = socialscan_res if socialscan_res is not None else {"skipped": "socialscan non installato"}

    prog.step("Controlli moderni (Gravatar/GitHub)")
    data["modern_checks"] = safe(lambda: run_modern_checks(email))

    prog.step("Search dorking")
    data["dorking"] = safe(lambda: run_dorking(email, "email"))

    prog.step("Telegram search")
    data["telegram"] = safe(lambda: run_telegram_search(email))

    prog.step("Dark web/leak (IntelligenceX)")
    data["darkweb"] = safe(lambda: run_intelx(f'"{email}"'))

    if do_analyze:
        prog.step("Sintesi Gemini")
        data["gemini_analysis"] = safe(lambda: gemini_analyze(data, email))

    prog.close()
    return data


def write_report(data, target, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    safe_name = re.sub(r"[^a-zA-Z0-9._+-]", "_", target)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = os.path.join(output_dir, f"{safe_name}_{timestamp}.json")
    txt_path = os.path.join(output_dir, f"{safe_name}_{timestamp}.txt")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(f"REPORT OSINT - {target}\n")
        f.write(f"Generato: {data.get('scanned_at')}\n")
        f.write("=" * 60 + "\n\n")
        if "gemini_analysis" in data and isinstance(data["gemini_analysis"], dict):
            analysis = data["gemini_analysis"].get("analysis")
            if analysis:
                f.write("--- SINTESI AI ---\n\n")
                f.write(analysis + "\n\n")
                f.write("=" * 60 + "\n\n")
        f.write("--- DATI GREZZI (JSON) ---\n\n")
        f.write(json.dumps(data, indent=2, ensure_ascii=False, default=str))

    return json_path, txt_path


# ---------------------------------------------------------------------------
# Modalità ricorsiva: segue automaticamente le diramazioni (sottodomini,
# typosquat registrati, CNPJ/PIVA trovati in pagina, reverse-IP solo se NON è
# hosting condiviso su larga scala) fino a una profondità configurabile.
# ---------------------------------------------------------------------------

# soglia sotto la quale una lista di reverse-IP è considerata un segnale reale
# (sopra questa soglia è quasi sempre hosting condiviso di massa - rumore, non lead)
REVERSE_IP_SIGNAL_THRESHOLD = 15

# provider email di massa - un dominio email trovato in un'email di contatto NON è un
# lead utile se è uno di questi (miliardi di persone/aziende scollegate li usano)
PUBLIC_EMAIL_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.it", "hotmail.com",
    "outlook.com", "live.com", "icloud.com", "me.com", "aol.com", "gmx.com",
    "protonmail.com", "proton.me", "yandex.com", "mail.com", "zoho.com",
    "hotmail.it", "libero.it", "virgilio.it", "tiscali.it", "alice.it",
    "bol.com.br", "uol.com.br", "terra.com.br", "ig.com.br",
}


def identify_leads(data, target, target_type, max_leads=3):
    """Analizza i risultati di una scansione e propone le diramazioni da seguire,
    con la motivazione esplicita per ciascuna - cosi' il report finale mostra sempre
    PERCHE' un target e' stato aggiunto, non solo che lo e' stato.

    Le diramazioni sono raccolte per CATEGORIA e poi intrecciate a rotazione (round-robin)
    prima di applicare il tetto max_leads - cosi' se ci sono piu' tipi di segnale (es. sia
    typosquat sia un dominio nuovo scoperto in un'email), nessuna categoria satura da sola
    tutto lo spazio disponibile a scapito delle altre. E' successo davvero: 3 typosquat
    riempivano l'intero max_leads di default, e domini/username nuovi scoperti restavano
    sempre esclusi indipendentemente da quanto fossero interessanti."""
    categories = []  # lista di liste, una per categoria

    if target_type != "domain":
        return []  # per ora la logica di diramazione e' pensata per i domini

    # 1. typosquat registrati
    typosquat_leads = []
    sim = data.get("similar_domains", {})
    if isinstance(sim, dict):
        for r in sim.get("registered_found", []):
            typosquat_leads.append({
                "target": r["domain"], "type": "domain",
                "reason": f"variante typosquat di {target}, risulta registrata e attiva (IP {r.get('resolved_ip')})",
            })
    categories.append(typosquat_leads)

    # 2. domini "nascosti" dentro le email trovate (es. cliente@mcgbank.org mentre si
    # scansiona mcgbank.com.br, o sac@fazbank.com.br - un terzo brand mai visto prima)
    email_domain_leads = []
    hf = data.get("http_fingerprint", {})
    ap = data.get("additional_pages", {})
    all_found_emails = set()
    if isinstance(hf, dict):
        all_found_emails.update(hf.get("emails_found", []))
    if isinstance(ap, dict):
        all_found_emails.update(ap.get("emails_found", []))
    email_domains_seen = set()
    for email in all_found_emails:
        if "@" not in email:
            continue
        email_domain = email.split("@")[1].lower()
        if email_domain in PUBLIC_EMAIL_PROVIDERS:
            continue  # gmail.com/hotmail.com/ecc. non sono lead utili, sono provider di massa
        if email_domain != target.lower() and email_domain not in email_domains_seen:
            email_domains_seen.add(email_domain)
            email_domain_leads.append({
                "target": email_domain, "type": "domain",
                "reason": f"dominio diverso trovato dentro un'email di contatto su {target} ({email})",
            })
    categories.append(email_domain_leads)

    # 3. username social ufficiali trovati (footer/header "seguici su...")
    social_leads = []
    sp = data.get("social_profiles_found", {})
    if isinstance(sp, dict):
        for platform, handles in sp.items():
            for h in handles[:1]:  # solo il primo per piattaforma
                social_leads.append({
                    "target": h, "type": "username",
                    "reason": f"handle {platform} ufficiale linkato da {target}",
                })
    categories.append(social_leads)

    # 4. CNPJ/PIVA trovati in pagina
    company_leads = []
    dca = data.get("discovered_company_analysis", {})
    if isinstance(dca, dict):
        for cnpj_num in dca.get("cnpj", {}).keys():
            company_leads.append({"target": cnpj_num, "type": "cnpj", "reason": f"CNPJ trovato nella homepage di {target}"})
        for piva_num in dca.get("piva", {}).keys():
            company_leads.append({"target": piva_num, "type": "piva", "reason": f"Partita IVA trovata nella homepage di {target}"})
    categories.append(company_leads)

    # 5. sottodomini reali (crt.sh)
    subdomain_leads = []
    sd = data.get("subdomains", {})
    if isinstance(sd, dict):
        subs = [s for s in sd.get("subdomains", []) if s not in (target, f"www.{target}")]
        for s in subs[:5]:
            subdomain_leads.append({"target": s, "type": "domain", "reason": f"sottodominio reale di {target} (trovato via crt.sh)"})
    categories.append(subdomain_leads)

    # 6. reverse-IP significativo (non hosting condiviso di massa)
    reverse_ip_leads = []
    ri = data.get("reverse_ip", {})
    if isinstance(ri, dict):
        co_hosted = ri.get("co_hosted_domains", [])
        if 0 < len(co_hosted) <= REVERSE_IP_SIGNAL_THRESHOLD:
            for d2 in co_hosted:
                reverse_ip_leads.append({
                    "target": d2, "type": "domain",
                    "reason": f"condivide l'IP con {target} - solo {len(co_hosted)} domini totali su quell'IP, non hosting condiviso di massa",
                })
        # se > soglia: scartato deliberatamente, e' rumore da hosting condiviso (vedi indagine MCG)
    categories.append(reverse_ip_leads)

    # intreccio round-robin: un elemento a turno da ogni categoria non vuota,
    # finche' non si raggiunge max_leads o si esauriscono tutte le categorie
    interleaved = []
    idx = 0
    while len(interleaved) < max_leads and any(categories):
        cat = categories[idx % len(categories)]
        if cat:
            interleaved.append(cat.pop(0))
        idx += 1
        if idx > 1000:  # sicurezza anti-loop, non dovrebbe mai scattare
            break

    return interleaved[:max_leads]


def dispatch_scan(target, target_type, do_analyze):
    """Richiama la pipeline di scansione corretta in base al tipo di target."""
    if target_type == "domain":
        return scan_domain(target, do_analyze)
    elif target_type == "cnpj":
        return scan_cnpj(target, do_analyze)
    elif target_type == "piva":
        return scan_piva(target, do_analyze)
    elif target_type == "email":
        return scan_email(target, do_analyze)
    elif target_type == "phone":
        return scan_phone(target, do_analyze)
    elif target_type == "username":
        return scan_username(target, do_analyze)
    return {"error": f"tipo di target non riconosciuto: {target_type}"}


def checkpoint_path_for(target, output_dir):
    safe_name = re.sub(r"[^a-zA-Z0-9._+-]", "_", target)
    return os.path.join(output_dir, f"checkpoint_{safe_name}.json")


def save_checkpoint(target, output_dir, visited, max_depth, max_leads, do_analyze):
    path = checkpoint_path_for(target, output_dir)
    try:
        os.makedirs(output_dir, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "root_target": target, "visited": sorted(visited),
                "max_depth": max_depth, "max_leads": max_leads, "do_analyze": do_analyze,
                "saved_at": datetime.now(timezone.utc).isoformat(),
            }, f, indent=2, ensure_ascii=False)
    except Exception:
        pass  # il checkpoint è un "nice to have": se il salvataggio fallisce non deve bloccare la scansione


def load_checkpoint(target, output_dir):
    path = checkpoint_path_for(target, output_dir)
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def clear_checkpoint(target, output_dir):
    path = checkpoint_path_for(target, output_dir)
    if os.path.exists(path):
        try:
            os.remove(path)
        except Exception:
            pass


def load_cached_scan(target, output_dir):
    """Carica l'ultimo report già salvato per un target, se esiste, senza rifare la
    scansione da capo - usato per riprendere un --follow-leads interrotto senza
    ripetere il lavoro già fatto sui nodi completati in precedenza."""
    scans = load_last_n_scans(target, output_dir, n=1)
    return scans[0][1] if scans else None


def investigate_recursive(target, target_type, max_depth, max_leads, do_analyze, output_dir,
                           visited=None, depth=0, resume_cache=None, checkpoint_root=None):
    """Scansiona un target e, se non ha raggiunto la profondità massima, segue
    automaticamente le diramazioni identificate da identify_leads(). Ritorna un
    albero (dict con 'children' annidati) invece di un singolo report piatto.

    Salva un checkpoint dopo ogni nodo completato: se l'esecuzione si interrompe
    (telefono che si blocca, rete che cade), rilanciando con --resume i nodi già
    completati vengono ricaricati dalla cache invece di essere rifatti da zero."""
    if visited is None:
        visited = set()
    if checkpoint_root is None:
        checkpoint_root = target  # la prima chiamata definisce il nome del file di checkpoint

    indent = "  " * depth
    prefix = "└─ " if depth > 0 else ""
    print(f"\n{indent}{prefix}[profondità {depth}] {target} ({target_type})")

    node = {"target": target, "type": target_type, "depth": depth}

    if target in visited:
        node["skipped"] = "già scansionato in questo albero, evitato per non fare loop"
        return node
    visited.add(target)

    used_cache = False
    if resume_cache and target in resume_cache:
        cached = load_cached_scan(target, output_dir)
        if cached:
            data = cached
            used_cache = True
            print(f"{indent}   (dalla cache: già completato in una sessione precedente)")
    if not used_cache:
        data = dispatch_scan(target, target_type, do_analyze)
        json_path, txt_path = write_report(data, target, output_dir)
        node["report_json"] = json_path
        node["report_txt"] = txt_path
    node["summary"] = data
    node["from_cache"] = used_cache

    save_checkpoint(checkpoint_root, output_dir, visited, max_depth, max_leads, do_analyze)

    if depth < max_depth:
        leads = identify_leads(data, target, target_type, max_leads)
        if leads:
            print(f"{indent}   → {len(leads)} diramazione/i trovata/e da seguire")
            node["children"] = []
            for lead in leads:
                child = investigate_recursive(
                    lead["target"], lead["type"], max_depth, max_leads, do_analyze,
                    output_dir, visited, depth + 1, resume_cache, checkpoint_root
                )
                child["lead_reason"] = lead["reason"]
                node["children"].append(child)

    return node



    return node


def print_tree_summary(node, indent=""):
    """Stampa un riepilogo leggibile dell'albero di scansione a fine esecuzione."""
    reason = f"  [{node['lead_reason']}]" if "lead_reason" in node else ""
    skipped = "  (già visitato, saltato)" if "skipped" in node else ""
    print(f"{indent}{node['target']} ({node['type']}){reason}{skipped}")
    for child in node.get("children", []):
        print_tree_summary(child, indent + "  ")


# ---------------------------------------------------------------------------
# Modalità correlazione (--correlate): analizza TUTTI i report già salvati e
# trova collegamenti nascosti tra i target (stesso IP, stesso CNPJ, stesso
# wallet crypto, stesso numero, stessa email, stesso amministratore societario,
# ecc.). E' il complemento "retrospettivo" di --follow-leads: quello segue le
# diramazioni IN AVANTI durante una scansione, questo guarda ALL'INDIETRO su
# tutto l'archivio.
# ---------------------------------------------------------------------------

GENERIC_INFRA_KEYWORDS = [
    "cloudflare", "amazon", "aws", "google", "microsoft", "azure", "namecheap",
    "godaddy", "ovh", "digitalocean", "wix", "squarespace", "fastly", "akamai",
    # piattaforme di domain parking di massa - migliaia di domini scollegati tra
    # loro condividono la stessa infrastruttura, esattamente come un CDN generico
    "sedo", "bodis", "trellian", "above.com", "parkingcrew", "dan.com",
    "parklogic", "namesilo",
]

# Certificati SSL gratuiti così diffusi (milioni di siti scollegati li usano) che
# condividerli non è MAI un segnale, nemmeno debole - scartati del tutto.
UBIQUITOUS_FREE_CAS = ["let's encrypt", "zerossl", "cloudflare inc"]

# Email/contatti "boilerplate" che compaiono in OGNI whois di un certo registrar/registro
# (es. l'indirizzo abuse standard di NIC.br o Namecheap) - zero valore come collegamento,
# vanno scartati del tutto, non solo declassati.
GENERIC_WHOIS_EMAIL_PATTERNS = [
    r"^abuse@", r"^mail-abuse@", r"^cert@cert\.br$", r"@markmonitor\.com$",
    r"@domainsbyproxy\.com$", r"whoisguard", r"@ripn\.net$",
]


def is_generic_whois_email(email):
    return any(re.search(p, email, re.I) for p in GENERIC_WHOIS_EMAIL_PATTERNS)


def is_generic_infra(value):
    if not value:
        return False
    v = value.lower()
    return any(k in v for k in GENERIC_INFRA_KEYWORDS)


def load_all_reports(reports_dir):
    """Carica tutti i report .json già salvati, tenendo la scansione più recente
    se lo stesso target è stato scansionato più volte. Ignora i file albero_*.json
    prodotti da --follow-leads (i singoli report al loro interno sono già inclusi
    come file separati)."""
    reports = {}
    for path in sorted(glob.glob(os.path.join(reports_dir, "*.json"))):
        if os.path.basename(path).startswith("albero_"):
            continue
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            target = data.get("target")
            if target:
                ts = data.get("scanned_at", "")
                if target not in reports or ts > reports[target].get("_scanned_at", ""):
                    data["_scanned_at"] = ts
                    data["_source_file"] = path
                    reports[target] = data
        except Exception:
            continue
    return reports


def extract_fingerprints(target, data):
    """Estrae gli identificatori 'forti' (bassa probabilità di coincidenza) e
    'deboli' (possibile infrastruttura condivisa) da un report."""
    strong = []
    weak = []

    # WHOIS grezzo: il campo "owner:"/"person:" e le email presenti nel testo sono
    # tra i segnali più forti in assoluto (es. "owner: EvoTrading S/A" nel whois di
    # un dominio diverso da evotrading stesso = collegamento diretto e ufficiale)
    w = data.get("whois", {})
    whois_raw = w.get("raw", "") if isinstance(w, dict) else ""
    if whois_raw:
        for m in re.finditer(r"(?im)^(?:owner|person):\s*(.+)$", whois_raw):
            nome = m.group(1).strip()
            # scarta valori-segnaposto tipici (redatto/privacy/not disclosed)
            if nome and not re.search(r"redact|privacy|not disclosed|withheld|\[.*\]", nome, re.I):
                strong.append(("WHOIS owner/person", nome.upper()))
        for email in re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", whois_raw):
            if not is_generic_whois_email(email):
                strong.append(("Email nel WHOIS", email.lower()))

    ip_info = data.get("ip_info", {})
    if isinstance(ip_info, dict):
        ip = ip_info.get("resolved_ip")
        isp = ip_info.get("isp") or ip_info.get("org") or ""
        if ip:
            (weak if is_generic_infra(isp) else strong).append(("IP", ip))

    rdns = data.get("reverse_dns", {})
    if isinstance(rdns, dict) and rdns.get("ptr_hostname"):
        ptr = rdns["ptr_hostname"]
        # se il PTR è identico all'IP stesso, non è un vero hostname (nessun record
        # PTR configurato) - evita di contarlo come un secondo indizio duplicato dell'IP
        if ptr != ip:
            weak.append(("Reverse DNS hostname", ptr))

    ssl_d = data.get("ssl", {})
    if isinstance(ssl_d, dict):
        issuer = ssl_d.get("issuer", {})
        org = issuer.get("organizationName") if isinstance(issuer, dict) else None
        if org and not is_generic_infra(org) and org.lower() not in UBIQUITOUS_FREE_CAS:
            weak.append(("SSL issuer org", org))

    hf = data.get("http_fingerprint", {})
    if isinstance(hf, dict):
        cids = hf.get("company_ids_found", {})
        for cnpj in cids.get("cnpj", []):
            strong.append(("CNPJ", cnpj))
        for piva in cids.get("piva", []):
            strong.append(("Partita IVA", piva))
        for email in hf.get("emails_found", []):
            strong.append(("Email nel sito", email.lower()))
        for phone in hf.get("phones_found", []):
            strong.append(("Telefono nel sito", phone))
        crypto = hf.get("crypto_addresses_found", {})
        for chain, addrs in crypto.items():
            for a in addrs:
                strong.append((f"Wallet {chain}", a))

    ap = data.get("additional_pages", {})
    if isinstance(ap, dict):
        for cnpj in ap.get("company_ids_found", {}).get("cnpj", []):
            strong.append(("CNPJ", cnpj))
        for piva in ap.get("company_ids_found", {}).get("piva", []):
            strong.append(("Partita IVA", piva))
        for email in ap.get("emails_found", []):
            strong.append(("Email nel sito", email.lower()))
        for phone in ap.get("phones_found", []):
            strong.append(("Telefono nel sito", phone))

    cr = data.get("company_registry", {})
    if isinstance(cr, dict) and cr.get("found"):
        for socio in cr.get("socios", []):
            nome = socio.get("nome")
            ruolo = (socio.get("qualificacao") or "").lower()
            # solo amministratori/presidenti/direttori - i semplici soci (spesso
            # centinaia di investitori) sono rumore ai fini della correlazione E
            # un problema di privacy se esposti come "collegamento" senza contesto
            if nome and ("administrador" in ruolo or "presidente" in ruolo or "diretor" in ruolo):
                strong.append(("Amministratore societario", nome.upper()))

    dca = data.get("discovered_company_analysis", {})
    if isinstance(dca, dict):
        for cnpj_num, info in dca.get("cnpj", {}).items():
            reg = info.get("registry", {})
            for socio in reg.get("socios", []):
                nome = socio.get("nome")
                ruolo = (socio.get("qualificacao") or "").lower()
                if nome and ("administrador" in ruolo or "presidente" in ruolo or "diretor" in ruolo):
                    strong.append(("Amministratore societario", nome.upper()))

    ttype = data.get("type")
    if ttype == "email":
        strong.append(("Email target", target.lower()))
    elif ttype == "phone":
        strong.append(("Telefono target", target))
    elif ttype in ("cnpj", "piva"):
        strong.append((ttype.upper(), target))

    return strong, weak


def build_correlation_index(reports):
    index = defaultdict(set)
    fingerprint_strength = {}
    for target, data in reports.items():
        strong, weak = extract_fingerprints(target, data)
        for fp in strong:
            index[fp].add(target)
            fingerprint_strength[fp] = "strong"
        for fp in weak:
            index[fp].add(target)
            fingerprint_strength.setdefault(fp, "weak")
    return index, fingerprint_strength


def find_correlations(reports, min_shared=2):
    index, strength = build_correlation_index(reports)
    correlations = []
    for fp, targets in index.items():
        if len(targets) >= min_shared:
            correlations.append({
                "type": fp[0], "value": fp[1],
                "strength": strength[fp], "targets": sorted(targets),
            })
    correlations.sort(key=lambda c: (c["strength"] != "strong", -len(c["targets"])))
    return correlations


def print_correlation_report(correlations, total_targets):
    print(f"\nAnalizzati {total_targets} target unici.\n")
    if not correlations:
        print("Nessun collegamento trovato tra i target analizzati.")
        return

    strong = [c for c in correlations if c["strength"] == "strong"]
    weak = [c for c in correlations if c["strength"] == "weak"]

    if strong:
        print("=" * 70)
        print(f"COLLEGAMENTI FORTI ({len(strong)}) - stesso identificatore univoco, coincidenza quasi impossibile")
        print("=" * 70)
        for c in strong:
            print(f"\n[{c['type']}] {c['value']}")
            print(f"  Presente in {len(c['targets'])} target:")
            for t in c["targets"]:
                print(f"    - {t}")

    if weak:
        print("\n" + "=" * 70)
        print(f"COLLEGAMENTI DA VERIFICARE ({len(weak)}) - infrastruttura condivisa, potrebbe essere coincidenza")
        print("=" * 70)
        for c in weak:
            print(f"\n[{c['type']}] {c['value']}")
            print(f"  Presente in {len(c['targets'])} target:")
            for t in c["targets"]:
                print(f"    - {t}")


def run_correlation(output_dir, min_shared=2):
    """Punto di ingresso della modalità --correlate: carica l'archivio e stampa
    il report di correlazione, salvando anche un JSON con i risultati."""
    if not os.path.isdir(output_dir):
        print(f"Cartella non trovata: {output_dir}")
        return
    reports = load_all_reports(output_dir)
    if not reports:
        print(f"Nessun report valido trovato in {output_dir}")
        return
    correlations = find_correlations(reports, min_shared)
    print_correlation_report(correlations, len(reports))

    corr_path = os.path.join(output_dir, f"correlazioni_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(corr_path, "w", encoding="utf-8") as f:
        json.dump({
            "total_targets_analyzed": len(reports),
            "targets": sorted(reports.keys()),
            "correlations": correlations,
        }, f, indent=2, ensure_ascii=False, default=str)
    print(f"\nRisultati salvati anche in: {corr_path}")


# ---------------------------------------------------------------------------
# Generazione report leggibile (--report) - da JSON grezzo a Markdown pulito,
# senza dipendenze esterne (nessun python-docx/node richiesto, gira ovunque).
# ---------------------------------------------------------------------------

def _md_kv(label, value):
    if value in (None, "", [], {}):
        return None
    if isinstance(value, (list, tuple)):
        if not value:
            return None
        return f"- **{label}**: {', '.join(str(v) for v in value)}"
    if isinstance(value, dict):
        return None
    return f"- **{label}**: {value}"


def generate_markdown_report(data):
    """Converte un report JSON (di qualsiasi tipo di target) in un Markdown leggibile,
    pensato per essere aperto in qualsiasi app note (incluso Obsidian) o convertito
    in altro formato in seguito, senza dipendenze esterne."""
    target = data.get("target", "?")
    ttype = data.get("type", "?")
    lines = [f"# Report OSINT — {target}", "", f"*Tipo: {ttype} · generato: {data.get('scanned_at', '?')}*", ""]

    if ttype == "domain":
        lines.append("## Infrastruttura")
        ip = data.get("ip_info", {})
        if isinstance(ip, dict):
            lines.append(_md_kv("IP", ip.get("resolved_ip")))
            lines.append(_md_kv("Hosting/ISP", ip.get("isp") or ip.get("org")))
            lines.append(_md_kv("Paese", ip.get("country")))
        w = data.get("whois", {})
        if isinstance(w, dict) and w.get("raw"):
            m = re.search(r"(?im)^owner:\s*(.+)$", w["raw"])
            if m:
                lines.append(_md_kv("WHOIS owner", m.group(1).strip()))
        lines.append("")

        hf = data.get("http_fingerprint", {})
        if isinstance(hf, dict):
            lines.append("## Sito")
            lines.append(_md_kv("Server", hf.get("server_header")))
            lines.append(_md_kv("Tecnologie rilevate", hf.get("technologies")))
            lines.append(_md_kv("Email trovate", hf.get("emails_found")))
            lines.append(_md_kv("Telefoni trovati", hf.get("phones_found")))
            sl = hf.get("social_links_found", {})
            if sl:
                for platform, handles in sl.items():
                    lines.append(_md_kv(f"Social ({platform})", handles))
            lines.append("")

        dca = data.get("discovered_company_analysis", {})
        if isinstance(dca, dict) and (dca.get("cnpj") or dca.get("piva")):
            lines.append("## Entità societarie trovate")
            for cnpj_num, info in dca.get("cnpj", {}).items():
                reg = info.get("registry", {})
                lines.append(f"### CNPJ {cnpj_num}")
                lines.append(_md_kv("Ragione sociale", reg.get("razao_social")))
                lines.append(_md_kv("Situazione", reg.get("situacao_cadastral")))
                admins = [s.get("nome") for s in reg.get("socios", []) if "administrador" in (s.get("qualificacao") or "").lower()]
                lines.append(_md_kv("Amministratori", admins))
            lines.append("")

        sim = data.get("similar_domains", {})
        if isinstance(sim, dict) and sim.get("registered_found"):
            lines.append("## Domini simili registrati (typosquat)")
            for r in sim["registered_found"]:
                lines.append(f"- {r['domain']} (IP {r.get('resolved_ip')})")
            lines.append("")

        dw = data.get("darkweb", {})
        if isinstance(dw, dict) and dw.get("count"):
            lines.append(f"## Dark web / leak\n{dw['count']} riscontri trovati (IntelligenceX)\n")

        tg = data.get("telegram", {})
        dc = tg.get("direct_handle_check", {}) if isinstance(tg, dict) else {}
        if dc.get("page_found"):
            lines.append("## Telegram")
            lines.append(_md_kv("Canale", dc.get("url")))
            lines.append(_md_kv("Titolo", dc.get("channel_title")))
            lines.append("")

    elif ttype == "email":
        hh = data.get("holehe", {})
        if isinstance(hh, dict):
            lines.append("## Holehe")
            lines.append(_md_kv("Servizi trovati", hh.get("found_on")))
            lines.append("")
        mc = data.get("modern_checks", {})
        if isinstance(mc, dict):
            lines.append("## Controlli aggiuntivi")
            grav = mc.get("gravatar", {})
            if grav.get("found"):
                lines.append(_md_kv("Gravatar", grav.get("profile_url")))
            breach = mc.get("breaches", {})
            if breach.get("found_in_breaches"):
                lines.append(_md_kv("Breach trovati", breach.get("breach_count")))
            lines.append("")

    elif ttype == "phone":
        pa = data.get("phone_analysis", {})
        if isinstance(pa, dict):
            lines.append("## Analisi numero")
            lines.append(_md_kv("Regione", pa.get("region")))
            lines.append(_md_kv("Operatore", pa.get("carrier")))
            lines.append(_md_kv("Tipo linea", pa.get("line_type")))
            lines.append(_md_kv("Numero business", pa.get("likely_business_number")))
            lines.append("")

    elif ttype in ("cnpj", "piva"):
        cr = data.get("company_registry", {})
        if isinstance(cr, dict):
            lines.append("## Registro societario")
            lines.append(_md_kv("Ragione sociale", cr.get("razao_social") or cr.get("name")))
            lines.append(_md_kv("Situazione", cr.get("situacao_cadastral") or cr.get("valid")))
            admins = [s.get("nome") for s in cr.get("socios", []) if "administrador" in (s.get("qualificacao") or "").lower()]
            if admins:
                lines.append(_md_kv("Amministratori", admins))
            lines.append("")

    # sintesi AI, se presente, sempre in fondo
    ga = data.get("gemini_analysis", {})
    if isinstance(ga, dict) and ga.get("analysis"):
        lines.append("## Sintesi AI")
        lines.append(ga["analysis"])
        lines.append("")

    return "\n".join(l for l in lines if l is not None)


def run_report_generation(json_path):
    """Punto di ingresso di --report: legge un JSON di report già salvato e genera
    un file Markdown leggibile accanto ad esso."""
    if not os.path.exists(json_path):
        print(f"File non trovato: {json_path}")
        return
    with open(json_path, encoding="utf-8") as f:
        data = json.load(f)
    md = generate_markdown_report(data)
    out_path = os.path.splitext(json_path)[0] + "_report.md"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"Report leggibile generato: {out_path}")


# ---------------------------------------------------------------------------
# Monitoraggio nel tempo (--diff) - confronta le ultime due scansioni dello
# stesso target e mostra solo cosa è cambiato, senza dover rileggere l'intero
# report a mano ogni volta.
# ---------------------------------------------------------------------------

def load_last_n_scans(target, output_dir, n=2):
    """Carica le ultime n scansioni salvate per lo stesso target, ordinate dalla
    più vecchia alla più recente."""
    safe_name = re.sub(r"[^a-zA-Z0-9._+-]", "_", target)
    candidates = sorted(glob.glob(os.path.join(output_dir, f"{safe_name}_*.json")))
    # esclude eventuali file albero_*/correlazioni_* che potrebbero combaciare per errore
    candidates = [c for c in candidates if not os.path.basename(c).startswith(("albero_", "correlazioni_"))]
    scans = []
    for path in candidates[-n:]:
        with open(path, encoding="utf-8") as f:
            scans.append((path, json.load(f)))
    return scans


def diff_lists(old_list, new_list):
    old_set, new_set = set(old_list or []), set(new_list or [])
    return {"aggiunti": sorted(new_set - old_set), "rimossi": sorted(old_set - new_set)}


def compute_diff(old_data, new_data):
    """Confronta due scansioni dello stesso target ed estrae solo le differenze
    rilevanti - pensato per un'indagine che dura mesi, dove interessa sapere
    'cosa è cambiato da ieri', non rileggere tutto da capo ogni volta."""
    diff = {
        "old_scan_date": old_data.get("scanned_at"),
        "new_scan_date": new_data.get("scanned_at"),
        "changes": {},
    }

    old_hf = old_data.get("http_fingerprint", {}) or {}
    new_hf = new_data.get("http_fingerprint", {}) or {}

    emails_diff = diff_lists(old_hf.get("emails_found"), new_hf.get("emails_found"))
    if emails_diff["aggiunti"] or emails_diff["rimossi"]:
        diff["changes"]["email_nel_sito"] = emails_diff

    phones_diff = diff_lists(old_hf.get("phones_found"), new_hf.get("phones_found"))
    if phones_diff["aggiunti"] or phones_diff["rimossi"]:
        diff["changes"]["telefoni_nel_sito"] = phones_diff

    old_ip = (old_data.get("ip_info", {}) or {}).get("resolved_ip")
    new_ip = (new_data.get("ip_info", {}) or {}).get("resolved_ip")
    if old_ip != new_ip:
        diff["changes"]["ip"] = {"prima": old_ip, "ora": new_ip}

    old_sub = (old_data.get("subdomains", {}) or {}).get("subdomains", [])
    new_sub = (new_data.get("subdomains", {}) or {}).get("subdomains", [])
    sub_diff = diff_lists(old_sub, new_sub)
    if sub_diff["aggiunti"] or sub_diff["rimossi"]:
        diff["changes"]["sottodomini"] = sub_diff

    old_ts = [r["domain"] for r in (old_data.get("similar_domains", {}) or {}).get("registered_found", [])]
    new_ts = [r["domain"] for r in (new_data.get("similar_domains", {}) or {}).get("registered_found", [])]
    ts_diff = diff_lists(old_ts, new_ts)
    if ts_diff["aggiunti"] or ts_diff["rimossi"]:
        diff["changes"]["domini_typosquat_registrati"] = ts_diff

    old_dw = (old_data.get("darkweb", {}) or {}).get("count", 0) or 0
    new_dw = (new_data.get("darkweb", {}) or {}).get("count", 0) or 0
    if old_dw != new_dw:
        diff["changes"]["dark_web_riscontri"] = {"prima": old_dw, "ora": new_dw}

    old_ssl = (old_data.get("ssl", {}) or {}).get("issuer", {})
    new_ssl = (new_data.get("ssl", {}) or {}).get("issuer", {})
    if old_ssl != new_ssl and (old_ssl or new_ssl):
        diff["changes"]["certificato_ssl_issuer"] = {"prima": old_ssl, "ora": new_ssl}

    old_tg = (old_data.get("telegram", {}) or {}).get("direct_handle_check", {}).get("members_hint")
    new_tg = (new_data.get("telegram", {}) or {}).get("direct_handle_check", {}).get("members_hint")
    if old_tg != new_tg and (old_tg or new_tg):
        diff["changes"]["telegram_membri"] = {"prima": old_tg, "ora": new_tg}

    old_crypto = (old_hf.get("crypto_addresses_found", {}) or {})
    new_crypto = (new_hf.get("crypto_addresses_found", {}) or {})
    for chain in set(list(old_crypto.keys()) + list(new_crypto.keys())):
        c_diff = diff_lists(old_crypto.get(chain), new_crypto.get(chain))
        if c_diff["aggiunti"] or c_diff["rimossi"]:
            diff["changes"][f"wallet_{chain}"] = c_diff

    return diff


def print_diff(diff, target):
    print(f"\nConfronto per {target}")
    print(f"  Scansione precedente: {diff['old_scan_date']}")
    print(f"  Scansione attuale:    {diff['new_scan_date']}")
    print()
    if not diff["changes"]:
        print("Nessuna differenza rilevata tra le due scansioni.")
        return
    print(f"Rilevate {len(diff['changes'])} categorie di cambiamento:\n")
    for category, change in diff["changes"].items():
        print(f"[{category}]")
        if isinstance(change, dict) and "aggiunti" in change:
            if change["aggiunti"]:
                print(f"  + aggiunti: {', '.join(str(x) for x in change['aggiunti'])}")
            if change["rimossi"]:
                print(f"  - rimossi: {', '.join(str(x) for x in change['rimossi'])}")
        else:
            print(f"  prima: {change.get('prima')}")
            print(f"  ora:   {change.get('ora')}")
        print()


def run_diff(target, output_dir):
    """Punto di ingresso di --diff: carica le ultime due scansioni dello stesso
    target e mostra solo cosa è cambiato."""
    scans = load_last_n_scans(target, output_dir, n=2)
    if len(scans) < 2:
        print(f"Servono almeno 2 scansioni salvate di '{target}' per fare un confronto - trovate {len(scans)}.")
        print("Rilancia una nuova scansione dello stesso target e riprova.")
        return
    (_, old_data), (_, new_data) = scans
    diff = compute_diff(old_data, new_data)
    print_diff(diff, target)

    diff_path = os.path.join(output_dir, f"diff_{re.sub(r'[^a-zA-Z0-9._+-]', '_', target)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(diff_path, "w", encoding="utf-8") as f:
        json.dump(diff, f, indent=2, ensure_ascii=False, default=str)
    print(f"Diff completo salvato in: {diff_path}")


# ---------------------------------------------------------------------------
# Rapporto PDF tecnico-forense (estensione osintr_ext): unisce i dati di questa scansione
# con l'analisi passiva del sito, degli indirizzi crypto multi-chain e dei flussi on-chain.
# ---------------------------------------------------------------------------

def resolve_pdf_path(value, target, output_dir):
    """'auto' (o --pdf senza valore) -> <output>/<target>_<timestamp>.pdf; altrimenti il percorso indicato."""
    if value and value != "auto":
        return value
    os.makedirs(output_dir, exist_ok=True)
    safe_name = re.sub(r"[^a-zA-Z0-9._+-]", "_", target)
    return os.path.join(output_dir, f"{safe_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")


def generate_forensic_pdf(data, pdf_path, args):
    """Genera il rapporto PDF dal risultato di scan_domain. Ritorna il percorso, oppure None se non possibile.
    Richiede la cartella osintr_ext/ accanto a questo script e il pacchetto 'reportlab'."""
    try:
        from osintr_ext import report as ext_report
        from osintr_ext.bridge import case_from_scan
        from osintr_ext.chains import Blocklists
        from osintr_ext.util import Http as ExtHttp
    except ImportError as e:
        if "reportlab" in str(e).lower():
            print(f"[!] PDF non generato: reportlab non utilizzabile ({str(e).splitlines()[0]}).\n"
                  "    Installa una versione compatibile con il tuo Python:  pip install \"reportlab<5\"")
        else:
            print(f"[!] PDF non generato: {e}. Serve la cartella osintr_ext/ accanto allo script.")
        return None
    if not isinstance(data, dict) or data.get("type") != "domain":
        print("[!] Il rapporto PDF forense è disponibile solo per i target di tipo dominio.")
        return None

    http = ExtHttp()
    blocklists = None
    if getattr(args, "pdf_ofac", False):
        bl = Blocklists()
        if bl.load_ofac(http):
            blocklists = bl
        else:
            print("[!] lista OFAC non scaricabile: controllo sanzioni sugli indirizzi saltato")
    reporter_country = args.reporter_country or get_reporter_country()
    meta = {k: v for k, v in {
        "analyst": args.analyst, "case_ref": args.case_ref, "reporter_country": reporter_country,
        "redact": not args.pdf_no_redact, "report_version": "1.0",
    }.items() if v}
    print("\nCostruzione del rapporto PDF (analisi passiva aggiuntiva di sito, indirizzi e flussi on-chain)...")
    try:
        case = case_from_scan(
            data, http, lang=args.pdf_lang, tx=args.tx, tx_chain=args.tx_chain,
            evidence=tuple(args.evidence or ()), meta=meta,
            etherscan_key=get_api_key("ETHERSCAN_API_KEY"), blocklists=blocklists,
            discover=not getattr(args, "pdf_no_discover", False))
        case_json = os.path.splitext(pdf_path)[0] + "_caso.json"
        with open(case_json, "w", encoding="utf-8") as f:
            json.dump(case, f, indent=2, ensure_ascii=False, default=str)
        ext_report.render(case, pdf_path, lang=args.pdf_lang, redact=not args.pdf_no_redact)
    except Exception as e:  # il PDF e' un extra: non deve mai far perdere il report gia' salvato
        print(f"[!] PDF non generato: {type(e).__name__}: {e}")
        return None
    lvl = case["assessment"]
    print(f"Rapporto PDF: {pdf_path}\n  caso (modificabile, rigenerabile con osintr_ext report): {case_json}\n"
          f"  valutazione automatica: {lvl['level'].upper()} (punteggio {lvl['score']}) - da rivedere a mano")
    return pdf_path


def main():
    parser = argparse.ArgumentParser(
        prog="osintr",
        description="Tool OSINT per domini, email, numeri di telefono, username, CNPJ e Partite IVA.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
ESEMPI D'USO:

  Prima di tutto, configura le chiavi API una volta sola (opzionale, ma evita di
  doverle reimpostare ad ogni sessione con 'export'):
    osintr --setup

  Scansione singola (comportamento base):
    osintr esempio.com
    osintr nome@esempio.com
    osintr +391234567890
    osintr username123
    osintr 12.345.678/0001-90        (CNPJ brasiliano)
    osintr IT02117980405             (Partita IVA italiana/UE)

  Modalità ricorsiva (--follow-leads): dopo la scansione, segue automaticamente
  sottodomini reali, typosquat registrati, CNPJ/PIVA trovati in pagina, domini
  nascosti nelle email, username social ufficiali e reverse-IP significativi
  (scarta l'hosting condiviso di massa), fino alla profondità scelta:
    osintr esempio.com --follow-leads
    osintr esempio.com --follow-leads --max-depth 2 --max-leads 6
    osintr esempio.com --follow-leads --resume    (riprende un'esecuzione interrotta)

  Modalità correlazione (--correlate): analizza tutti i report già salvati e trova
  collegamenti nascosti tra i target (stesso CNPJ, wallet, telefono, IP, ecc.):
    osintr --correlate                          (analizza solo l'archivio esistente)
    osintr esempio.com --correlate              (scansiona esempio.com, poi correla con l'archivio)
    osintr esempio.com --follow-leads --correlate   (scansiona + diramazioni + correlazione finale)

  Monitoraggio nel tempo (--diff): rilancia una scansione già fatta in passato e
  mostra solo cosa è cambiato da allora (nuovo sottodominio, nuovo typosquat
  registrato, membri Telegram, ecc.):
    osintr esempio.com --diff

  Report leggibile da un JSON già salvato, senza rifare la scansione:
    osintr --report ./osint_reports/esempio.com_20260101_120000.json

  Rapporto PDF tecnico-forense (solo domini; richiede osintr_ext/ e reportlab):
    osintr esempio.com --pdf                       (salva <output>/<target>_<data>.pdf)
    osintr esempio.com --pdf rapporto.pdf --pdf-lang en --reporter-country IT
    osintr esempio.com --pdf --tx 0x... --tx-chain bsc --evidence screenshot.png --pdf-ofac
    osintr --report ./osint_reports/esempio.com_20260101_120000.json --pdf

  Altre opzioni utili:
    osintr esempio.com --no-analyze             (salta la sintesi AI Gemini, più veloce)
    osintr esempio.com --output ./report_MCG    (cartella di output personalizzata)
""",
    )
    parser.add_argument("target", nargs="?", default=None,
                        help="dominio, email, telefono, username, CNPJ o Partita IVA. Opzionale con --setup, --correlate o --report.")
    parser.add_argument("--output", default="./osint_reports", help="cartella di output (default ./osint_reports)")
    parser.add_argument("--no-analyze", action="store_true", help="salta la sintesi automatica con Gemini")
    parser.add_argument("--follow-leads", action="store_true",
                        help="segue automaticamente le diramazioni (sottodomini, typosquat, CNPJ/PIVA trovati, reverse-IP significativi) fino alla profondità massima")
    parser.add_argument("--max-depth", type=int, default=1, help="profondità massima delle diramazioni con --follow-leads (default 1)")
    parser.add_argument("--max-leads", type=int, default=3, help="numero massimo di diramazioni seguite per ogni target (default 3)")
    parser.add_argument("--resume", action="store_true",
                        help="con --follow-leads: riprende un'esecuzione precedente interrotta, ricaricando dalla cache i nodi già completati invece di rifarli")
    parser.add_argument("--correlate", action="store_true",
                        help="analizza tutti i report già salvati nella cartella di output e trova collegamenti nascosti tra i target (stesso CNPJ, wallet, telefono, IP, ecc.). Se combinato con un target, scansiona prima quello e poi lo confronta con l'archivio esistente.")
    parser.add_argument("--min-shared", type=int, default=2,
                        help="con --correlate: numero minimo di target che devono condividere un identificatore per essere segnalati (default 2)")
    parser.add_argument("--setup", action="store_true",
                        help="avvia il wizard di configurazione: salva le chiavi API una volta sola in ~/.osintr/config.json, senza bisogno di 'export' ad ogni sessione")
    parser.add_argument("--report", metavar="JSON_FILE", default=None,
                        help="genera un report Markdown leggibile da un file JSON già salvato, senza rifare la scansione")
    parser.add_argument("--diff", action="store_true",
                        help="dopo la scansione, confronta il risultato con l'ultima scansione precedente dello stesso target e mostra solo cosa è cambiato")
    pdfg = parser.add_argument_group("rapporto PDF tecnico-forense (osintr_ext)")
    pdfg.add_argument("--pdf", nargs="?", const="auto", default=None, metavar="FILE",
                      help="genera un rapporto PDF tecnico-forense (solo domini). Senza valore salva in cartella di output. "
                           "Con --report genera il PDF da un JSON gia' salvato (ripete in modo passivo le verifiche su sito e blockchain)")
    pdfg.add_argument("--pdf-lang", choices=["it", "en"], default="it", help="lingua del PDF (default it)")
    pdfg.add_argument("--pdf-no-redact", action="store_true",
                      help="NON abbreviare indirizzi e TxID nel PDF (solo per copie riservate alle autorita')")
    pdfg.add_argument("--pdf-no-discover", action="store_true",
                      help="nel PDF non leggere gli endpoint/pagine citati dal sito (meno richieste al sito, meno indirizzi trovati)")
    pdfg.add_argument("--pdf-ofac", action="store_true", help="controlla gli indirizzi crypto sulla lista OFAC SDN")
    pdfg.add_argument("--tx", metavar="HASH", help="hash della transazione EVM del versamento/prelievo della vittima")
    pdfg.add_argument("--tx-chain", default="bsc", choices=["bsc", "eth", "polygon", "arbitrum", "base", "optimism", "avalanche"],
                      help="rete della transazione --tx (default bsc)")
    pdfg.add_argument("--evidence", action="append", metavar="FILE", help="file di prova da hashare (SHA-256) nel PDF; ripetibile")
    pdfg.add_argument("--analyst", help="nome dell'analista nel PDF")
    pdfg.add_argument("--case-ref", help="riferimento pratica nel PDF")
    pdfg.add_argument("--reporter-country", metavar="CC",
                      help="paese di chi segnala (es. IT): sceglie le autorita' indicate nel PDF. "
                           "Se omesso, viene chiesto una volta e salvato (vedi anche --setup)")
    args = parser.parse_args()

    if args.setup:
        run_setup_wizard()
        return

    if args.report:
        run_report_generation(args.report)
        if args.pdf:
            try:
                with open(args.report, encoding="utf-8") as f:
                    saved = json.load(f)
            except (OSError, ValueError) as e:
                print(f"[!] impossibile leggere {args.report}: {e}")
                return
            generate_forensic_pdf(saved, resolve_pdf_path(args.pdf, str(saved.get("target", "report")), args.output), args)
        return

    if not args.target and not args.correlate:
        parser.error("specifica un target, oppure usa --setup / --correlate / --report da soli (vedi --help per esempi)")

    do_analyze = not args.no_analyze

    if args.target:
        target = sanitize_target(args.target)
        print(f"Target: {target}")
        if is_email_target(target):
            target_type = "email"
        elif is_cnpj_target(target):
            target_type = "cnpj"
        elif is_piva_target(target):
            target_type = "piva"
        elif is_phone_target(target):
            target_type = "phone"
        elif is_username_target(target):
            target_type = "username"
        else:
            target_type = "domain"

        if args.follow_leads:
            resume_cache = None
            if args.resume:
                checkpoint = load_checkpoint(target, args.output)
                if checkpoint:
                    resume_cache = set(checkpoint.get("visited", []))
                    print(f"Ripresa da checkpoint: {len(resume_cache)} target già completati verranno caricati dalla cache\n")
                else:
                    print("Nessun checkpoint trovato per questo target - si parte da zero.\n")

            print(f"Modalità ricorsiva attiva: profondità massima {args.max_depth}, max {args.max_leads} diramazioni per target\n")
            tree = investigate_recursive(target, target_type, args.max_depth, args.max_leads, do_analyze, args.output, resume_cache=resume_cache)
            clear_checkpoint(target, args.output)  # esecuzione completata, il checkpoint non serve più

            tree_path = os.path.join(args.output, f"albero_{re.sub(r'[^a-zA-Z0-9._+-]', '_', target)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(tree_path, "w", encoding="utf-8") as f:
                json.dump(tree, f, indent=2, ensure_ascii=False, default=str)

            print("\n" + "=" * 60)
            print("ALBERO DI INVESTIGAZIONE")
            print("=" * 60)
            print_tree_summary(tree)
            print(f"\nAlbero completo salvato in: {tree_path}")
            print(f"Report individuali salvati in: {args.output}/")
            if args.pdf:
                root_data = load_cached_scan(target, args.output)
                if root_data:
                    generate_forensic_pdf(root_data, resolve_pdf_path(args.pdf, target, args.output), args)
                else:
                    print("[!] PDF non generato: report del target radice non trovato nella cartella di output")
        else:
            data = dispatch_scan(target, target_type, do_analyze)
            json_path, txt_path = write_report(data, target, args.output)
            print(f"\nReport salvato:\n  {json_path}\n  {txt_path}")

            if do_analyze and isinstance(data.get("gemini_analysis"), dict):
                analysis = data["gemini_analysis"].get("analysis")
                error = data["gemini_analysis"].get("error")
                if analysis:
                    print("\n" + "=" * 60)
                    print("SINTESI AI")
                    print("=" * 60)
                    print(analysis)
                elif error:
                    print(f"\n[!] Sintesi Gemini non disponibile: {error}")

            if args.pdf:
                generate_forensic_pdf(data, resolve_pdf_path(args.pdf, target, args.output), args)

        if args.diff:
            print("\n" + "=" * 60)
            print("MODALITA' DIFF - confronto con la scansione precedente")
            print("=" * 60)
            run_diff(target, args.output)

    if args.correlate:
        print("\n" + "=" * 60)
        print("MODALITA' CORRELAZIONE - analisi dell'intero archivio")
        print("=" * 60)
        run_correlation(args.output, args.min_shared)


if __name__ == "__main__":
    main()
