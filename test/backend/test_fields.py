from pcap_backend.fields import FieldCatalog

SAMPLE = "\n".join(
    [
        "P\tHypertext Transfer Protocol\thttp",
        "P\tHTTP2\thttp2",
        "P\tInternet Protocol Version 4\tip",
        "F\tSource Address\tip.src\tFT_IPv4\tip\t\t0x0\tSource IP",
        "F\tSource Host\tip.src_host\tFT_STRING\tip\t\t0x0\t",
        "F\tDestination Address\tip.dst\tFT_IPv4\tip\t\t0x0\t",
        "F\tHost\thttp.host\tFT_STRING\thttp\t\t0x0\t",
        "F\tMixed Case\tfoo.Bar\tFT_UINT8\tfoo\tBASE_DEC\t0x0\t",
        "garbage line",
    ]
)


def test_prefix_search_is_sorted_and_exact_first() -> None:
    cat = FieldCatalog.parse(SAMPLE)
    res = cat.search("ip.src", 10)
    assert [f["name"] for f in res["fields"]] == ["ip.src", "ip.src_host"]
    assert res["fields"][0] == {
        "name": "ip.src",
        "desc": "Source Address",
        "type": "FT_IPv4",
        "proto": "ip",
        "blurb": "Source IP",
    }
    assert res["truncated"] is False


def test_prefix_search_covers_protocols_and_ignores_case() -> None:
    cat = FieldCatalog.parse(SAMPLE)
    res = cat.search("HTT", 10)
    assert [p["name"] for p in res["protocols"]] == ["http", "http2"]
    assert [f["name"] for f in res["fields"]] == ["http.host"]
    assert [f["name"] for f in cat.search("foo.b", 5)["fields"]] == ["foo.Bar"]


def test_limit_and_truncation() -> None:
    cat = FieldCatalog.parse(SAMPLE)
    res = cat.search("ip.", 2)
    assert len(res["fields"]) == 2
    assert res["truncated"] is True
    empty = cat.search("", 0)
    assert empty == {"protocols": [], "fields": [], "truncated": True}
    assert cat.search("zzz", 5) == {"protocols": [], "fields": [], "truncated": False}


def test_membership() -> None:
    cat = FieldCatalog.parse(SAMPLE)
    assert "ip.src" in cat
    assert "HTTP" in cat
    assert "ip.sr" not in cat
    assert 42 not in cat


def test_merged_outputs_are_deduplicated() -> None:
    cat = FieldCatalog.parse(
        SAMPLE + "\n" + SAMPLE + "\nF\tExtra\textra.f\tFT_UINT8\textra\t\t0x0\t"
    )
    assert [f["name"] for f in cat.search("ip.src", 10)["fields"]] == ["ip.src", "ip.src_host"]
    assert "extra.f" in cat
