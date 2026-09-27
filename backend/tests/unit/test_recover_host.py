import subprocess

from recovery.scripts.recover_host import restore_project_firewall


def test_restore_project_firewall_success(monkeypatch):
    commands = []

    def fake_run(command, check, capture_output, text):
        commands.append(command)

        return subprocess.CompletedProcess(
            command,
            0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        "recovery.scripts.recover_host.subprocess.run",
        fake_run,
    )

    result = restore_project_firewall()

    assert result is True

    command_text = [
        " ".join(command)
        for command in commands
    ]

    assert any(
        "flush chain inet arbr_isolation input" in command
        for command in command_text
    )

    assert any(
        "flush chain inet arbr_isolation output" in command
        for command in command_text
    )

    assert all(
        "iptables -F" not in command
        for command in command_text
    )


def test_restore_project_firewall_failure(monkeypatch):
    def fake_run(command, check, capture_output, text):
        raise subprocess.CalledProcessError(
            1,
            command,
        )

    monkeypatch.setattr(
        "recovery.scripts.recover_host.subprocess.run",
        fake_run,
    )

    result = restore_project_firewall()

    assert result is False