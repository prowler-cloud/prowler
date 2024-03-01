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

    def get_checks_to_execute_by_audit_resources(self):
        """
        get_checks_to_execute_by_audit_resources returns a set of checks based on the input resources to scan.

        This is a fallback that returns None if the service has not implemented this function.
        """
