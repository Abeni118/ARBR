from backend.app.isolation.firewall import NftablesFirewall
from backend.app.isolation.host_control import HostControl
from backend.app.isolation.isolation_manager import IsolationManager


def test_real_kali_isolation():
    host_control = HostControl(
        host="192.168.56.101",
        username="kali",
        password="kali",
    )

    firewall = NftablesFirewall(host_control.execute)
    manager = IsolationManager(firewall)

    result = manager.isolate_host(
        host_id="kali-01",
        reason="Integration test",
        risk_level="HIGH",
    )

    assert result["success"] is True
    assert firewall.is_isolated("kali-01") is True

    result = manager.restore_host("kali-01")

    assert result["success"] is True
    assert firewall.is_isolated("kali-01") is False