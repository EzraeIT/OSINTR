#!/bin/sh
# Installa il comando "osintr" nel sistema, cosi' si lancia come:
#   osintr esempio.com --pdf --ofac
# invece di:
#   python3 /percorso/osint_recon.py esempio.com --pdf --ofac
#
# Uso: posizionati nella cartella con osint_recon.py e osintr_ext/, poi:
#   sh install.sh
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ ! -f "$HERE/osint_recon.py" ]; then
    echo "osint_recon.py non trovato in $HERE. Esegui questo script dalla cartella giusta."
    exit 1
fi
mkdir -p /usr/local/bin
cat > /usr/local/bin/osintr <<WRAP
#!/bin/sh
exec python3 "$HERE/osint_recon.py" "\$@"
WRAP
chmod +x /usr/local/bin/osintr
echo "Fatto. Da ora puoi lanciare:  osintr <target> --pdf --ofac [altre opzioni]"
echo "Verifica con:  osintr --help"
