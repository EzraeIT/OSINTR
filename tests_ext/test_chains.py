from osintr_ext import chains
from osintr_ext.fakehttp import FakeHttp
from osintr_ext.demo import AMOUNT, EXCH, TX, WA, WB, WC, build_fake_http
from osintr_ext.util import Finding


def test_decode_transfer_and_snapshots():
    http = build_fake_http()
    d = chains.decode_transfer_tx(http, "bsc", TX)
    assert d["token"] == "USDT" and abs(d["amount"] - AMOUNT) < 1e-9
    assert d["from"].lower() == EXCH.lower() and d["to"].lower() == WA.lower() and d["status"] == "ok"
    c = chains.evm_snapshot(http, "bsc", WC)
    assert c["type"] == "EOA" and c["nonce"] == 99_677 and round(c["tokens"]["USDT"], 2) == 21975.24


def test_trace_forward_follows_matching_amount():
    http = build_fake_http()
    d = chains.decode_transfer_tx(http, "bsc", TX)
    hops = chains.trace_forward(http, "bsc", d["to"], "USDT", "demo", d["amount"], d["timestamp"])
    assert [h["to"].lower() for h in hops] == [WB.lower(), WC.lower()]
    assert hops[0]["delay_s"] == 2400 and hops[1]["delay_s"] == 454
    assert all(h["matched_amount"] and h["to_type"] == "EOA" for h in hops)


def test_collector_interpretation_thresholds():
    low = {"chain": "bsc", "type": "EOA", "nonce": 7, "tokens": {}, "native": 0}
    mid = {**low, "nonce": 250}
    high = {**low, "nonce": 5000}
    assert chains.interpret_snapshot("0xabc", low, "t") == []
    assert chains.interpret_snapshot("0xabc", mid, "t")[0].severity == "medium"
    assert chains.interpret_snapshot("0xabc", high, "t")[0].severity == "high"
    contract = {**high, "type": "contract"}
    assert chains.interpret_snapshot("0xabc", contract, "t") == []


def test_blocklists_and_findings(tmp_path):
    f = tmp_path / "bad.txt"
    f.write_text("# comment\n0xAbC123 reason\n")
    bl = chains.Blocklists()
    bl.load_file(str(f), "Lista interna")
    bl.sets["OFAC SDN"] = {"0xdead"}
    assert bl.match("0xABC123") == ["Lista interna"]
    codes = {x.code for x in chains.list_findings("0xdead", ["OFAC SDN"], "b")}
    assert codes == {"ONC_SANCTIONED"}
    assert {x.code for x in chains.list_findings("0xabc123", ["Lista interna"], "b")} == {"ONC_BLOCKLIST"}


def test_solana_snapshot():
    http = FakeHttp()

    def rpc(method, params):
        if method == "getAccountInfo":
            return {"value": {"lamports": 2_500_000_000, "executable": False}}
        if method == "getSignaturesForAddress":
            return [{"signature": str(i)} for i in range(1000)]
        if method == "getTokenAccountsByOwner":
            return {"value": [{"account": {"data": {"parsed": {"info": {"tokenAmount": {"uiAmount": 12.5}}}}}}]}
    http.add_rpc(chains.SOLANA_RPC[0], rpc)
    s = chains.solana_snapshot(http, "SoLaNaDemoAddress")
    assert s["type"] == "account" and s["native"] == 2.5 and s["tokens"]["USDT"] == 12.5 and s["sig_cap_hit"]
    f = chains.interpret_snapshot("SoLaNaDemoAddress", s, "t")
    assert f and f[0].code == "ONC_COLLECTOR"


def test_doge_snapshot():
    http = FakeHttp()
    http.add(chains.DOGE_API + "/DDemo/balance", {"final_balance": 10_000_000, "total_received": 900_000_000,
                                                  "final_n_tx": 80}, exact=False)
    s = chains.doge_snapshot(http, "DDemo")
    assert s["balance"] == 0.1 and s["received"] == 9.0 and s["tx_count"] == 80
    assert chains.interpret_snapshot("DDemo", s, "t")[0].code == "ONC_STATS_PASSTHROUGH"


def test_unreachable_node_returns_none():
    assert chains.evm_snapshot(FakeHttp(), "bsc", WA) is None
    assert chains.solana_snapshot(FakeHttp(), "x") is None
