from backend.app.isolation.firewall import MockFirewall


def test_isolate_host():
    firewall = MockFirewall()

    result = firewall.isolate("host-01")

    assert result is True
    assert firewall.is_isolated("host-01") is True


def test_restore_host():
    firewall = MockFirewall()

    firewall.isolate("host-01")

    result = firewall.restore("host-01")

    assert result is True
    assert firewall.is_isolated("host-01") is False


def test_restore_non_isolated_host():
    firewall = MockFirewall()

    result = firewall.restore("host-01")

    assert result is False


def test_multiple_hosts():
    firewall = MockFirewall()

    firewall.isolate("host-01")
    firewall.isolate("host-02")

    assert firewall.is_isolated("host-01") is True
    assert firewall.is_isolated("host-02") is True

    firewall.restore("host-01")

    assert firewall.is_isolated("host-01") is False
    assert firewall.is_isolated("host-02") is True