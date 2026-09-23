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