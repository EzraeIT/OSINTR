"""Verifica geografica dell'indirizzo societario dichiarato (geo-OSINT "statico", non tracciamento di persone).

Principio: geocodifica un indirizzo che una fonte ufficiale (VIES, registro CNPJ) o il sito stesso ha gia'
dichiarato pubblicamente, per vedere se esiste davvero e se e' coerente con il paese dichiarato. Non localizza
nessuna persona, non triangola nulla, non stima alcuna posizione in tempo reale: e' un controllo di plausibilita'
su un dato gia' pubblico, dello stesso tipo del controllo RDAP sul dominio o VIES sulla partita IVA.

Fonte: Nominatim (OpenStreetMap), gratuita, senza chiave. Rispetta la loro usage policy: il client HTTP
condiviso (util.Http) gia' applica un throttling per host e uno User-Agent identificabile, qui portato a
>= 1 secondo tra le richieste come richiesto da Nominatim.
"""
from __future__ import annotations

import urllib.parse
from typing import Optional

from .util import Finding

NOMINATIM_URL = "https://nominatim.openstreetmap.org/search"
NOMINATIM_MIN_DELAY = 1.0   # policy Nominatim: non piu' di 1 richiesta al secondo

# classi OSM che indicano un indirizzo risolto a livello di edificio/via (preciso), non solo di citta'/regione
PRECISE_CLASSES = {"building", "office", "shop", "amenity", "house", "place:house"}
VAGUE_TYPES = {"administrative", "city", "town", "village", "state", "country", "postcode", "suburb"}


def geocode(http, address: str, min_delay: float = NOMINATIM_MIN_DELAY) -> Optional[dict]:
    """Geocodifica un indirizzo via Nominatim. Ritorna None se non trovato o la risposta non e' valida."""
    address = (address or "").strip()
    if not address or len(address) < 4:
        return None
    if getattr(http, "delay", min_delay) < min_delay:
        http.delay = min_delay   # garantisce la policy di Nominatim anche se il client ha un delay minore
    q = urllib.parse.urlencode({"q": address, "format": "jsonv2", "addressdetails": 1, "limit": 1})
    d = http.get_json(f"{NOMINATIM_URL}?{q}")
    if not isinstance(d, list) or not d:
        return None
    hit = d[0]
    addr = hit.get("address") or {}
    cc = (addr.get("country_code") or "").upper()
    osm_type = hit.get("type", "")
    osm_class = hit.get("class", "")
    precise = osm_class in PRECISE_CLASSES or (osm_class == "place" and osm_type not in VAGUE_TYPES)
    return {
        "query": address,
        "display_name": hit.get("display_name"),
        "lat": hit.get("lat"), "lon": hit.get("lon"),
        "country_code": cc,
        "osm_class": osm_class, "osm_type": osm_type,
        "precise": precise,
        "source": "Nominatim (OpenStreetMap)",
    }


def assess_declared_address(geo: Optional[dict], address_text: str, expected_country: Optional[str],
                            basis: str) -> list[Finding]:
    """Confronta l'esito della geocodifica con il paese atteso (es. il paese della partita IVA/CNPJ dichiarati).
    Le euristiche qui sono indicative: un indirizzo vago o non trovato non e' prova di frode, solo un segnale
    da verificare a mano (es. domiciliazione presso uno studio, sede in co-working, errore di trascrizione)."""
    fs: list[Finding] = []
    exp = (expected_country or "").upper()
    if geo is None:
        if address_text and len(address_text.strip()) >= 4:
            fs.append(Finding("GEO_ADDRESS_NOT_FOUND", "medium", "low", "fact", "entity", basis,
                              {"address": address_text.strip()}))
        return fs
    if exp and geo["country_code"] and geo["country_code"] != exp:
        fs.append(Finding("GEO_COUNTRY_MISMATCH", "medium", "medium", "fact", "entity", basis,
                          {"address": address_text.strip(), "expected": exp,
                           "found": geo["country_code"].upper()}))
    if not geo["precise"]:
        fs.append(Finding("GEO_ADDRESS_VAGUE", "low", "medium", "interpretation", "entity", basis,
                          {"address": address_text.strip(), "resolved": geo["display_name"] or "n/d"}))
    return fs


def cnpj_address_text(cnpj_registry: dict) -> str:
    """Compone una stringa indirizzo dai campi via/numero/bairro/comune/stato di BrasilAPI, se presenti."""
    parts = [cnpj_registry.get(k) for k in ("logradouro", "numero", "bairro", "municipio", "uf")]
    return ", ".join(str(p) for p in parts if p)
