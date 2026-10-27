import hashlib

from osintr_ext import addresses as A

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\x00"))) + out


def h(seed: str, n: int) -> bytes:
    return hashlib.sha256(seed.encode()).digest()[:n]


def test_evm_found_and_placeholder_ignored():
    real = "0x" + h("a", 20).hex()
    text = f"pay {real} not 0x{'0' * 40} nor 0x{'ab' * 20}"
    fams = [(f.family, f.address) for f in A.find_addresses(text)]
    assert ("evm", real) in fams
    assert all(a != "0x" + "0" * 40 for _, a in fams)


def test_btc_legacy_checksum_enforced():
    good = A.b58encode_check(b"\x00" + h("btc", 20))
    bad = good[:-1] + ("2" if good[-1] != "2" else "3")
    assert [f.family for f in A.find_addresses(f"btc: {good}")] == ["btc"]
    assert A.find_addresses(f"btc: {bad}") == []


def test_bech32_vector():
    addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
    assert [f.family for f in A.find_addresses(addr)] == ["btc"]


def test_tron_and_doge():
    tron = A.b58encode_check(b"\x41" + h("tron", 20))
    doge = A.b58encode_check(b"\x1e" + h("doge", 20))
    assert tron.startswith("T") and doge.startswith("D")
    assert A.classify(tron) == "tron"
    assert A.classify(doge) == "doge"


def test_solana_needs_context_on_pages_but_not_when_user_supplies_it():
    sol = b58encode(h("sol", 32))
    assert 32 <= len(sol) <= 44
    # in una pagina: senza contesto Solana è solo una stringa base58 qualunque (hash, id, token)
    assert A.find_addresses(f"session id {sol}") == []
    assert [f.family for f in A.find_addresses(f"Deposit USDT on Solana: {sol}")] == ["sol"]
    # fornito esplicitamente dall'analista
    assert A.classify(sol) == "sol"


def test_hints_from_context():
    evm = "0x" + h("hint", 20).hex()
    f = A.find_addresses(f"USDT (TRC20 or BEP20) {evm}")[0]
    assert "bsc" in f.hints and "tron" in f.hints


def test_classify_rejects_garbage():
    assert A.classify("hello") == ""
    assert A.classify("0x123") == ""
