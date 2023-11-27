from abc import ABC, abstractmethod


class CloudProvider(ABC):
    audit_resources: list = None
    is_quiet: bool
    output_modes: list
    output_directory: str
    allowlist_file: str
    bulk_checks_metadata: dict
    verbose: str
    output_filename: str
    only_logs: bool
    unix_timestamp: bool

    @abstractmethod
    def setup_session(self):
        pass

    @abstractmethod
    def print_credentials(self):
        pass

    # @abstractmethod
    # def create_outputs(self):
    #     pass

    def validate_arguments(self):
        pass
