from unittest.mock import MagicMock, patch

from backend.app.isolation.host_control import HostControl


@patch("backend.app.isolation.host_control.paramiko.SSHClient")
def test_execute(mock_ssh_client):
    client = MagicMock()
    mock_ssh_client.return_value = client

    stdout = MagicMock()
    stderr = MagicMock()

    stdout.channel.recv_exit_status.return_value = 0
    stdout.read.return_value = b"connected"
    stderr.read.return_value = b""

    client.exec_command.return_value = (
        MagicMock(),
        stdout,
        stderr,
    )

    controller = HostControl(
        host="192.168.56.101",
        username="kali",
        password="test",
    )

    exit_code, output, error = controller.execute("echo connected")

    assert exit_code == 0
    assert output == "connected"
    assert error == ""


@patch("backend.app.isolation.host_control.paramiko.SSHClient")
def test_is_reachable(mock_ssh_client):
    client = MagicMock()
    mock_ssh_client.return_value = client

    stdout = MagicMock()
    stderr = MagicMock()

    stdout.channel.recv_exit_status.return_value = 0
    stdout.read.return_value = b"connected"
    stderr.read.return_value = b""

    client.exec_command.return_value = (
        MagicMock(),
        stdout,
        stderr,
    )

    controller = HostControl(
        host="192.168.56.101",
        username="kali",
        password="test",
    )

    assert controller.is_reachable() is True