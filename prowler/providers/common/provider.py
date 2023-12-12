from abc import ABC, abstractmethod


class CloudProvider(ABC):
    @abstractmethod
    def setup_session(self):
        pass

    @abstractmethod
    def print_credentials(self):
        pass

    def validate_arguments(self):
        pass
