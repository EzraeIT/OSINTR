from osintr_ext import geo
from osintr_ext.fakehttp import FakeHttp

NOMINATIM = geo.NOMINATIM_URL


def _hit(country_code="pt", osm_class="building", osm_type="yes", display="Rua Exemplo 1, Lisboa, Portugal"):
    return [{"display_name": display, "lat": "38.71", "lon": "-9.14", "class": osm_class, "type": osm_type,
             "address": {"country_code": country_code}}]


def test_geocode_building_level_is_precise():
    http = FakeHttp()
    http.add(NOMINATIM, _hit(), exact=False)
    g = geo.geocode(http, "Rua Exemplo 1, Lisboa, Portugal")
    assert g["precise"] is True and g["country_code"] == "PT"
    assert g["display_name"].startswith("Rua Exemplo")


def test_geocode_vague_city_level_result():
    http = FakeHttp()
    http.add(NOMINATIM, _hit(osm_class="place", osm_type="city", display="Lisboa, Portugal"), exact=False)
    g = geo.geocode(http, "Lisboa")
    assert g["precise"] is False


def test_geocode_not_found_returns_none():
    http = FakeHttp()
    http.add(NOMINATIM, [], exact=False)
    assert geo.geocode(http, "Via Inventata 999, Nessunlandia") is None


def test_geocode_rejects_empty_or_too_short_queries_without_a_request():
    http = FakeHttp()
    assert geo.geocode(http, "") is None
    assert geo.geocode(http, "  ") is None
    assert geo.geocode(http, "ab") is None
    assert http.calls == []           # nessuna richiesta inviata per un indirizzo vuoto/troppo corto


def test_geocode_enforces_nominatim_minimum_delay():
    http = FakeHttp()
    http.delay = 0.1
    http.add(NOMINATIM, _hit(), exact=False)
    geo.geocode(http, "Rua Exemplo 1, Lisboa, Portugal")
    assert http.delay >= geo.NOMINATIM_MIN_DELAY


def test_assess_not_found():
    fs = geo.assess_declared_address(None, "Via Finta 1, Roma", "IT", "VIES + Nominatim")
    assert [f.code for f in fs] == ["GEO_ADDRESS_NOT_FOUND"]
    assert fs[0].severity == "medium" and fs[0].kind == "fact"


def test_assess_not_found_with_blank_address_gives_no_finding():
    assert geo.assess_declared_address(None, "", "IT", "basis") == []


def test_assess_country_mismatch():
    http = FakeHttp()
    http.add(NOMINATIM, _hit(country_code="pt"), exact=False)
    g = geo.geocode(http, "Rua Exemplo 1, Lisboa")
    fs = geo.assess_declared_address(g, "Rua Exemplo 1, Lisboa", "IT", "VIES + Nominatim")
    codes = {f.code for f in fs}
    assert "GEO_COUNTRY_MISMATCH" in codes
    m = next(f for f in fs if f.code == "GEO_COUNTRY_MISMATCH")
    assert m.params["expected"] == "IT" and m.params["found"] == "PT"


def test_assess_matching_country_and_precise_gives_no_findings():
    http = FakeHttp()
    http.add(NOMINATIM, _hit(country_code="pt"), exact=False)
    g = geo.geocode(http, "Rua Exemplo 1, Lisboa")
    fs = geo.assess_declared_address(g, "Rua Exemplo 1, Lisboa", "PT", "VIES + Nominatim")
    assert fs == []


def test_assess_vague_result_flagged():
    http = FakeHttp()
    http.add(NOMINATIM, _hit(osm_class="place", osm_type="city", display="Lisboa, Portugal"), exact=False)
    g = geo.geocode(http, "Lisboa")
    fs = geo.assess_declared_address(g, "Lisboa", "PT", "basis")
    assert [f.code for f in fs] == ["GEO_ADDRESS_VAGUE"]
    assert fs[0].kind == "interpretation"


def test_cnpj_address_text_assembles_available_fields():
    full = {"logradouro": "Rua Teste", "numero": "100", "bairro": "Centro", "municipio": "Sao Paulo", "uf": "SP"}
    assert geo.cnpj_address_text(full) == "Rua Teste, 100, Centro, Sao Paulo, SP"
    partial = {"logradouro": "Rua Teste", "municipio": "Sao Paulo"}
    assert geo.cnpj_address_text(partial) == "Rua Teste, Sao Paulo"
    assert geo.cnpj_address_text({}) == ""
