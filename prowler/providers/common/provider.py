from abc import ABC, abstractmethod


class Provider(ABC):
    @abstractmethod
    def setup_session(self):
        pass

    @abstractmethod
    def print_credentials(self):
        pass

    def validate_arguments(self):
        pass
