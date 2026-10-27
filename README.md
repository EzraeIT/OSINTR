# osintr

Strumento OSINT in Python per l'analisi di domini, email, numeri di telefono, username e identificativi
societari (Partita IVA italiana, CNPJ brasiliano e, tramite registri pubblici, entità in circa 45 paesi).
Include un modulo di analisi tecnico-forense di siti sospetti e indirizzi crypto, con generazione automatica
di un rapporto PDF.

Pensato per chi fa due diligence, verifica venditori o operatori prima di un pagamento, o analizza siti
sospettati di truffa (schemi di finto arbitraggio, rendimenti promessi, raccolta fondi non autorizzata).

## Cosa fa

**Ricognizione del dominio**
Sottodomini (Certificate Transparency), cronologia su Wayback Machine, domini simili/typosquat, reverse IP,
geolocalizzazione e ASN, porte esposte note a Shodan, reputazione IP (AbuseIPDB), CVE note sullo stack
rilevato, email trovate e il loro coinvolgimento in violazioni di dati note.

**Analisi del sito**
Legge HTML e JavaScript pubblici per individuare codice che genera dati finanziari finti lato client,
promesse di rendimento e la loro coerenza interna, linguaggio di garanzia/urgenza, pagine legali mancanti,
header di sicurezza, cookie, CORS. Scopre inoltre, in modo passivo (solo richieste GET, nessun login), gli
endpoint e le pagine che **il sito stesso cita** nel proprio codice — senza indovinare percorsi — e riconosce
categorie di dati interessanti (saldo, transazioni, arbitraggio, rendimenti, dati account).

**Indirizzi e flussi crypto**
Rileva indirizzi su 7 reti EVM (Ethereum, BSC, Polygon, Arbitrum, Base, Optimism, Avalanche), Bitcoin,
Litecoin, Dogecoin, TRON e Solana. Per ciascuno: saldo, tipo di wallet, token. Con l'hash di una transazione,
traccia i passaggi successivi dei fondi. Controllo opzionale sulla lista sanzioni OFAC.

**Verifica società**
VIES per le partite IVA UE, GLEIF per il LEI, BrasilAPI per il CNPJ, e per ogni altro paese un rimando al
registro imprese e all'autorità di vigilanza competente (circa 45 paesi coperti).

**Rapporto PDF**
Tutto confluisce in un rapporto tecnico-forense in italiano o inglese: sintesi del rischio con punteggio,
matrice che separa fatti, interpretazioni e limiti, diagramma del flusso dei fondi, hash delle prove,
azioni raccomandate verso le autorità competenti per il paese di chi segnala.

## Esempio

Il rapporto in `examples/esempio_rapporto.pdf` è generato interamente con dati sintetici e inventati
(`python -m osintr_ext selftest`) — nessun sito, società o indirizzo reale.
Mostra la struttura completa del rapporto: sintesi, matrice di rischio, flusso dei fondi, azioni raccomandate.

## Installazione

Richiede Python 3.9+.

    pip install requests "reportlab<5"
    git clone https://github.com/<tuo-utente>/osintr.git
    cd osintr
    sh install.sh        # installa il comando "osintr" nel sistema (opzionale)

`reportlab<5` perché la versione 5.x richiede Python 3.10+; su versioni precedenti usa la 4.x. Senza
reportlab installato, lo strumento funziona lo stesso: salta solo la generazione del PDF.

Variabili d'ambiente opzionali (nessuna è obbligatoria): `ETHERSCAN_API_KEY`, `OPENCORPORATES_API_KEY`,
`COMPANIES_HOUSE_KEY`, `OPENSANCTIONS_API_KEY`.

## Uso

    osintr esempio.com                          # scansione, senza PDF
    osintr esempio.com --pdf --ofac              # scansione completa + rapporto PDF, controllo sanzioni
    osintr esempio.com --pdf --tx 0xHASH --tx-chain bsc --evidence screenshot.png
    osintr utente@esempio.com                    # anche email, telefono, username, P.IVA, CNPJ

Alla prima scansione con `--pdf`, lo strumento chiede una volta sola il paese di chi segnala (per scegliere
le autorità giuste nelle azioni raccomandate) e lo salva per le volte successive.

Senza installare il comando globale: `python3 osint_recon.py esempio.com --pdf`.

## Test

    python3 test_osint_recon.py      # 47 test sullo script principale
    python3 -m pytest tests_ext      # 80 test sul modulo di analisi forense

Tutti offline, con client HTTP finto: nessuna rete reale viene interrogata durante i test.

## Limiti, onestamente

- I giudizi sono euristiche automatiche: possono dare falsi positivi, e vanno sempre riviste da una persona.
  Il rapporto non è un parere legale né una perizia giudiziaria, e non attribuisce indirizzi a persone.
- La scoperta di endpoint è volutamente limitata a ciò che il sito stesso rende raggiungibile e cita nel suo
  codice pubblico: nessun tentativo di indovinare percorsi, nessun login, nessun bypass di autenticazione.
- Le API pubbliche usate (RPC, BrasilAPI, BlockCypher, mempool.space, crt.sh...) hanno limiti di frequenza e
  possono cambiare nel tempo.
- Evita di usarlo per pubblicare dati su persone private: rischi di diffamazione e di violare il GDPR.

## Licenza

MIT — vedi [LICENSE](LICENSE).
