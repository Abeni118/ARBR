from abc import ABC, abstractmethod


class Firewall(ABC):
    @abstractmethod
    def isolate(self, host_id: str) -> bool:
        pass

    @abstractmethod
    def restore(self, host_id: str) -> bool:
        pass

    @abstractmethod
    def is_isolated(self, host_id: str) -> bool:
        pass


class NftablesFirewall(Firewall):
    TABLE = "arbr_isolation"

    def __init__(self, ssh_command):
        self.ssh_command = ssh_command

    def _run(self, command: str) -> tuple[int, str, str]:
        return self.ssh_command(command)

    def isolate(self, host_id: str) -> bool:
        commands = [
            f"sudo -n nft add rule inet {self.TABLE} input counter drop",
            f"sudo -n nft add rule inet {self.TABLE} output counter drop",
        ]

        for command in commands:
            exit_code, _, _ = self._run(command)

            if exit_code != 0:
                return False

        return True

    def restore(self, host_id: str) -> bool:
        commands = [
            f"sudo -n nft flush chain inet {self.TABLE} input",
            f"sudo -n nft flush chain inet {self.TABLE} output",
        ]

        for command in commands:
            exit_code, _, _ = self._run(command)

            if exit_code != 0:
                return False

        return self._rebuild_base_rules()

    def _rebuild_base_rules(self) -> bool:
        commands = [
            f"sudo -n nft add rule inet {self.TABLE} input iifname lo accept",
            f"sudo -n nft add rule inet {self.TABLE} input ct state established,related accept",
            f"sudo -n nft add rule inet {self.TABLE} input ip saddr 192.168.56.1 tcp dport 22 accept",
            f"sudo -n nft add rule inet {self.TABLE} output oifname lo accept",
            f"sudo -n nft add rule inet {self.TABLE} output ct state established,related accept",
        ]

        for command in commands:
            exit_code, _, _ = self._run(command)

            if exit_code != 0:
                return False

        return True

    def is_isolated(self, host_id: str) -> bool:
        command = f"sudo -n nft list chain inet {self.TABLE} input"

        exit_code, output, _ = self._run(command)

        if exit_code != 0:
            return False

        return "drop" in output


class MockFirewall(Firewall):
    def __init__(self):
        self.isolated_hosts = set()

    def isolate(self, host_id: str) -> bool:
        self.isolated_hosts.add(host_id)
        return True

    def restore(self, host_id: str) -> bool:
        if host_id not in self.isolated_hosts:
            return False

        self.isolated_hosts.remove(host_id)
        return True

    def is_isolated(self, host_id: str) -> bool:
        return host_id in self.isolated_hosts