from backend.app.isolation.isolation_manager import IsolationManager
from backend.app.isolation.firewall import MockFirewall
from backend.app.isolation.isolation_manager import IsolationManager

def test_host_status_is_normal_by_default():
    manager = IsolationManager(MockFirewall())

    result = manager.get_status("host-01")

    assert result["host_id"] == "host-01"
    assert result["status"] == "NORMAL"


def test_isolate_host():
    firewall = MockFirewall()
    manager = IsolationManager(firewall)

    result = manager.isolate_host(
        host_id="host-01",
        reason="Suspicious ransomware activity",
        risk_level="CRITICAL",
    )

    assert result["host_id"] == "host-01"
    assert result["status"] == "ISOLATED"
    assert result["success"] is True


def test_isolated_host_status():
    manager = IsolationManager(MockFirewall())

    manager.isolate_host(
        host_id="host-01",
        reason="Suspicious activity",
        risk_level="HIGH",
    )

    result = manager.get_status("host-01")

    assert result["status"] == "ISOLATED"
    assert result["details"]["risk_level"] == "HIGH"


def test_already_isolated_host():
    manager = IsolationManager(MockFirewall())

    manager.isolate_host(
        host_id="host-01",
        reason="Suspicious activity",
        risk_level="HIGH",
    )

    result = manager.isolate_host(
        host_id="host-01",
        reason="Another suspicious activity",
        risk_level="CRITICAL",
    )

    assert result["status"] == "ALREADY_ISOLATED"
    assert result["success"] is True


def test_restore_host():
    manager = IsolationManager(MockFirewall())

    manager.isolate_host(
        host_id="host-01",
        reason="Suspicious activity",
        risk_level="CRITICAL",
    )

    result = manager.restore_host("host-01")

    assert result["host_id"] == "host-01"
    assert result["status"] == "RESTORED"
    assert result["success"] is True


def test_restore_non_isolated_host():
    manager = IsolationManager(MockFirewall())

    result = manager.restore_host("host-01")

    assert result["status"] == "NOT_ISOLATED"
    assert result["success"] is False