import os

import paramiko


class HostControl:
    def __init__(
        self,
        host: str,
        username: str,
        password: str | None = None,
        port: int = 22,
    ):
        self.host = host
        self.username = username
        self.password = password
        self.port = port

    def execute(self, command: str) -> tuple[int, str, str]:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=10,
            )

            stdin, stdout, stderr = client.exec_command(command)

            exit_code = stdout.channel.recv_exit_status()
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()

            return exit_code, output, error

        finally:
            client.close()

    def is_reachable(self) -> bool:
        exit_code, _, _ = self.execute("echo connected")
        return exit_code == 0