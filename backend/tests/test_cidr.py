from shadowmcp.discovery.cidr_targets import expand_targets


def test_cidr_without_port_is_refused() -> None:
    urls, errors = expand_targets(["10.0.0.0/30"], [])
    assert urls == []
    assert errors[0].code == "cidr_refused"


def test_single_host_network_expands() -> None:
    urls, errors = expand_targets(["127.0.0.1/32"], [3333])
    assert errors == []
    assert urls == ["http://127.0.0.1:3333/mcp"]


def test_small_cidr_expands() -> None:
    urls, errors = expand_targets(["10.0.0.0/30"], [3333])
    assert errors == []
    assert urls == [
        "http://10.0.0.1:3333/mcp",
        "http://10.0.0.2:3333/mcp",
    ]