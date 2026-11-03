from osintr_ext import entity, registries
from osintr_ext.fakehttp import FakeHttp


def test_parse_vat_and_similarity():
    assert entity.parse_vat("PT 123.456.789", None) == ("PT", "123456789")
    assert entity.parse_vat("123456789", "pt") == ("PT", "123456789")
    assert entity.name_similarity("Word Cripto, Unipessoal Lda", "WORD CRIPTO") == 1.0
    assert entity.name_similarity("Alpha Trading Ltd", "Beta Holdings GmbH") == 0.0


def test_company_mentions_with_legal_suffixes():
    m = entity.find_company_mentions("(c) 2026 DEMO CAPITAL, UNIPESSOAL LDA - NIPC 500000000. Also Acme Trading Ltd")
    assert any("DEMO CAPITAL" in n for n in m["names"])
    assert "500000000" in m["ids"]


def test_cnpj_active_inactive_and_missing():
    http = FakeHttp()
    http.add("https://brasilapi.com.br/api/cnpj/v1/11222333000181",
             {"cnpj": "11222333000181", "razao_social": "EMPRESA TESTE LTDA", "descricao_situacao_cadastral": "BAIXADA",
              "data_inicio_atividade": "2020-01-10", "uf": "SP"})
    res, fs = entity.lookup_entity(http, name="Gamma Trading", country="BR", vat="11.222.333/0001-81")
    codes = {f.code for f in fs}
    assert res["country"] == "BR" and res["cnpj"]["status"] == "BAIXADA"
    assert "ENT_CNPJ_INACTIVE" in codes and "ENT_NAME_MISMATCH" in codes

    res2, fs2 = entity.lookup_entity(FakeHttp(), country="BR", vat="99888777000166")
    assert "ENT_CNPJ_NOT_FOUND" in {f.code for f in fs2}


def test_vies_used_only_for_eu_countries():
    http = FakeHttp()
    res, fs = entity.lookup_entity(http, name="Acme Inc", country="US", vat="123456789")
    assert "vies" not in res
    assert not any("vies" in c for c in http.calls)


def test_offshore_hint_and_sources_for_any_country():
    _, fs = entity.lookup_entity(FakeHttp(), name="Zeta Capital Ltd", country="SC")
    assert "ENT_OFFSHORE_JURISDICTION" in {f.code for f in fs}
    for cc in ("IT", "US", "BR", "AU", "SG", "AE", "ZA", "JP"):
        labels = [a for a, _ in registries.verification_sources(cc)]
        assert len(labels) > len(registries.GLOBAL_SOURCES)
    # paese sconosciuto: restano le fonti globali
    assert registries.verification_sources("XX") == registries.GLOBAL_SOURCES


def test_country_helpers():
    assert registries.country_from_vat("PT123456789") == "PT"
    assert registries.country_from_vat("123456789") == ""
    assert registries.country_from_domain("example.co.uk") == "GB"   # conta solo il TLD
    assert registries.country_from_domain("shop.it") == "IT"
    assert registries.normalize_country("uk") == "GB"


def test_vies_address_is_geocoded_automatically():
    http = FakeHttp()
    http.add("https://ec.europa.eu/taxation_customs/vies/rest-api/ms/PT/vat/123456789",
             {"isValid": True, "name": "DEMO LDA", "address": "Rua Exemplo 1, Lisboa"})
    http.add("https://nominatim.openstreetmap.org/search",
             [{"display_name": "Rua Exemplo 1, Lisboa, Portugal", "lat": "38.7", "lon": "-9.1",
               "type": "building", "class": "building", "address": {"country_code": "pt"}}], exact=False)
    res, fs = entity.lookup_entity(http, name="Demo Lda", country="PT", vat="123456789")
    assert res["geo"]["country_code"] == "PT" and res["geo"]["precise"] is True
    assert not any(f.code.startswith("GEO_") for f in fs)   # tutto coerente: nessun finding geo


def test_cnpj_address_is_geocoded_and_mismatch_detected():
    http = FakeHttp()
    http.add("https://brasilapi.com.br/api/cnpj/v1/11222333000181",
             {"cnpj": "11222333000181", "razao_social": "EMPRESA TESTE LTDA",
              "descricao_situacao_cadastral": "ATIVA", "logradouro": "Rua Teste", "numero": "1",
              "bairro": "Centro", "municipio": "Sao Paulo", "uf": "SP"})
    http.add("https://nominatim.openstreetmap.org/search",
             [{"display_name": "Lisboa, Portugal", "lat": "38.7", "lon": "-9.1",
               "type": "city", "class": "place", "address": {"country_code": "pt"}}], exact=False)
    res, fs = entity.lookup_entity(http, name="Empresa Teste", country="BR", vat="11.222.333/0001-81")
    codes = {f.code for f in fs}
    assert "GEO_COUNTRY_MISMATCH" in codes and "GEO_ADDRESS_VAGUE" in codes
