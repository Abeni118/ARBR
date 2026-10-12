
from types import SimpleNamespace
from unittest.mock import Mock

from backend.app.isolation.decision_handlers import (
    IsolationRecoveryHandlers,
    RecoveryRequest,
)


def make_decision():
    return SimpleNamespace(
        host_id="host-01",
        reason="Suspicious ransomware activity",
        risk_level=SimpleNamespace(value="CRITICAL"),
    )


def test_isolate_calls_isolation_manager():
    isolation_manager = Mock()
    isolation_manager.isolate_host.return_value = {
        "success": True,
        "status": "ISOLATED",
    }

    recovery_manager = Mock()
    handlers = IsolationRecoveryHandlers(
        isolation_manager,
        recovery_manager,
    )

    assert handlers.isolate(make_decision()) is True

    isolation_manager.isolate_host.assert_called_once_with(
        host_id="host-01",
        reason="Suspicious ransomware activity",
        risk_level="CRITICAL",
    )


def test_isolate_returns_false_when_isolation_fails():
    isolation_manager = Mock()
    isolation_manager.isolate_host.return_value = {
        "success": False,
        "status": "ISOLATION_FAILED",
    }

    handlers = IsolationRecoveryHandlers(
        isolation_manager,
        Mock(),
    )

    assert handlers.isolate(make_decision()) is False


def test_recovery_fails_without_request_provider():
    handlers = IsolationRecoveryHandlers(
        Mock(),
        Mock(),
    )

    assert handlers.recover(make_decision()) is False
    assert (
        handlers.last_recovery_result["reason"]
        == "RECOVERY_REQUEST_NOT_CONFIGURED"
    )


def test_recover_calls_recovery_manager():
    recovery_manager = Mock()
    recovery_manager.recover.return_value = {
        "success": True,
        "status": "COMPLETED",
    }

    request = RecoveryRequest(
        backup_path="trusted-backup",
        restore_path="restore-target",
        expected_hashes={"document.txt": "abc123"},
        expected_files=["document.txt"],
    )

    handlers = IsolationRecoveryHandlers(
        Mock(),
        recovery_manager,
        recovery_request_provider=lambda decision: request,
    )

    assert handlers.recover(make_decision()) is True

    recovery_manager.recover.assert_called_once_with(
        backup_path="trusted-backup",
        restore_path="restore-target",
        expected_hashes={"document.txt": "abc123"},
        expected_files=["document.txt"],
    )


def test_recover_returns_false_when_recovery_fails():
    recovery_manager = Mock()
    recovery_manager.recover.return_value = {
        "success": False,
        "reason": "BACKUP_NOT_TRUSTED",
    }

    request = RecoveryRequest(
        backup_path="untrusted-backup",
        restore_path="restore-target",
        expected_hashes={"document.txt": "abc123"},
    )

    handlers = IsolationRecoveryHandlers(
        Mock(),
        recovery_manager,
        recovery_request_provider=lambda decision: request,
    )

    assert handlers.recover(make_decision()) is False