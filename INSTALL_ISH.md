# osintr + osintr_ext: scansione OSINT con rapporto PDF tecnico-forense

Metti `osint_recon.py`, `test_osint_recon.py`, `install.sh` e la cartella `osintr_ext/` nella stessa cartella.
Serve in più solo `pip install "reportlab<5"` (reportlab 5.x richiede Python 3.10+; con Python 3.9, per esempio su iSH, usa la 4.x). Il resto dello script funziona come prima, anche senza l'estensione.

## Comando unico "osintr" (consigliato)
Una volta sola:
    sh install.sh
Da quel momento, da qualunque cartella:
    osintr esempio.com --pdf --ofac
invece di `python3 osint_recon.py esempio.com --pdf --ofac`. È lo stesso programma, solo più comodo da richiamare.
Se preferisci non installarlo, `python3 osint_recon.py ...` funziona sempre allo stesso modo.

## Rapporto PDF: UN comando, UN tool
`osint_recon.py` e l'estensione (`osintr_ext/`) non sono due strumenti separati: `--pdf` fa scattare dentro lo
stesso processo sia la scansione del dominio (sottodomini, Wayback, IP, porte, violazioni, sanzioni) sia l'analisi
del sito e della blockchain. Lancia sempre il comando `osintr` (o `python3 osint_recon.py`): **non** `python3 -m
osintr_ext case` da solo, che fa *solo* la parte di sito/blockchain e salta sottodomini, Wayback, IP e porte.

    osintr esempio.com --pdf                                  # PDF nella cartella di output
    osintr esempio.com --pdf rapporto.pdf --pdf-lang en --reporter-country IT
    osintr esempio.com --pdf --tx 0x... --tx-chain bsc --evidence screenshot.png --pdf-ofac \
           --analyst "Nome" --case-ref PRATICA-1
    osintr --report ./osint_reports/esempio.com_XXXX.json --pdf   # da un JSON già salvato (ripete in modo passivo le verifiche su sito e blockchain)
    osintr esempio.com --follow-leads --pdf                   # PDF del solo target radice

Accanto al PDF viene salvato `<nome>_caso.json`: puoi aggiungere a mano `manual_findings` e rigenerare con
`python -m osintr_ext report <nome>_caso.json --pdf nuovo.pdf`. Il PDF è sempre in copia "privacy-safe"
(indirizzi e TxID abbreviati) salvo `--pdf-no-redact`. Solo domini; un errore nel PDF non cancella mai il report già salvato.

## Cosa entra nel PDF
- **Dalla tua scansione**: sottodomini CT, Wayback, domini simili (typosquat) anche sullo stesso IP, reverse IP,
  IP/ASN/TLS, porte note a Shodan, AbuseIPDB, CVE da NVD, violazioni delle email trovate (mascherate), IntelligenceX,
  CNPJ/Partita IVA con screening sanzioni. Compaiono in una sezione dedicata e come finding `INF_*` nella matrice di rischio.
- **Analisi dell'estensione**: codice JavaScript che genera "operazioni" casuali, rendimenti e loro incoerenza,
  pagine legali, indirizzi crypto su EVM (7 reti), BTC, LTC, DOGE, TRON, Solana, flusso dei fondi con `--tx`,
  OFAC, registri e fonti ufficiali per circa 45 paesi.

## Ricerca automatica degli indirizzi e dei dati interessanti (senza doverli conoscere)
Oltre a HTML e file JavaScript, l'estensione legge gli **endpoint citati dal codice del sito** (es. `/api/finance`)
e le **pagine interne linkate** che parlano di deposito, wallet, piani, arbitraggio, account, cronologia ecc.
Per ogni risposta leggibile riconosce campi per categoria (`wallet_saldo`, `transazioni`, `arbitraggio_trading`,
`rendimenti_commissioni`, `account_profilo`, `cronologia_statistiche`): sono indicatori per dire all'analista dove
guardare, non una prova che i dati siano reali o utilizzabili.

Regole, sempre:
- solo GET, nessun login né cookie, nessun invio di dati;
- solo lo stesso host del sito (mai domini terzi);
- solo percorsi che il **sito stesso cita** nel suo codice o nei suoi link — **nessun elenco di nomi comuni da tentare**
  (niente `/api/wallet`, `/api/accounts` provati "a tentativi": se il sito non li cita da nessuna parte nel codice
  pubblico, lo strumento non li cerca);
- un endpoint che risponde con una pagina di login o uno stato 401/403 viene **registrato** (URL, stato, se richiede
  login) e **non viene letto oltre**: nessun tentativo di aggirare l'autenticazione;
- tetto di 80 endpoint e 12 pagine per scansione, per restare entro un numero di richieste ragionevole.

Risultato nel PDF: tabella con URL, stato (con l'indicazione "(login)" quando serve l'accesso), indirizzi trovati e
categorie riconosciute. A terminale, `osintr_ext case` stampa lo stesso riepilogo. Tutto finisce anche nel JSON del
caso (`site.endpoints`, `site.pages`), così puoi ispezionarlo o filtrarlo tu stesso.

Per disattivarla: `--no-discover` (estensione) o `--pdf-no-discover` (script).

**Limite reale, non aggirabile:** lo strumento trova solo ciò che il sito rende raggiungibile pubblicamente e cita nel
suo codice. Non trova endpoint mai citati da nessuna parte, non recupera dati dietro login, e non prova a indovinare
nomi di percorso. Se un dato compare solo dopo l'accesso con un account, va recuperato da te (tab Rete del browser,
con un tuo account) e passato con `--address` o inserito a mano nel JSON del caso.

## Uso autonomo dell'estensione (solo per indirizzi o un sito, senza dati di dominio)
    python -m osintr_ext case --url https://sito.example --country PT --vat 500000000 --pdf r.pdf --json caso.json
    python -m osintr_ext addr 0x... bc1... T... --ofac
    python -m osintr_ext selftest --pdf esempio.pdf           # dati sintetici, offline

## Test
    python3 -m unittest test_osint_recon        # 47 test (38 tuoi + 9 di integrazione)
    python3 -m pytest tests_ext                 # 64 test dell'estensione
Tutti offline, con client HTTP finto: nessun servizio reale è stato interrogato nel collaudo.

## Limiti
- I giudizi sono euristiche da rivedere a mano: il PDF non è un parere legale né una perizia e non attribuisce wallet a persone.
- Un errore di rete non viene mai trattato come indizio; il PDF ripete in modo passivo alcune richieste (sito, RPC) già fatte dallo script.
- Gli URL dei registri nazionali sono home page istituzionali: ricontrollali prima dell'uso in sede legale.
- Evita di pubblicare nomi di privati (diffamazione, GDPR).
