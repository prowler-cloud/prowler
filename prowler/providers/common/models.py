from dataclasses import dataclass
from os import makedirs
from os.path import isdir

from pydantic.v1 import BaseModel

from prowler.providers.common.provider import Provider


# TODO: include this for all the providers
class Audit_Metadata(BaseModel):
    services_scanned: int
    # We can't use a set in the expected
    # checks because the set is unordered
    expected_checks: list
    completed_checks: int
    audit_progress: int


class ProviderOutputOptions:
    status: list[str]
    output_modes: list
    output_directory: str
    bulk_checks_metadata: dict
    verbose: str
    output_filename: str
    only_logs: bool
    unix_timestamp: bool

    def __init__(self, arguments, bulk_checks_metadata):
        self.status = getattr(arguments, "status", None)
        self.output_modes = getattr(arguments, "output_formats", None)
        self.output_directory = getattr(arguments, "output_directory", None)
        self.verbose = getattr(arguments, "verbose", None)
        self.bulk_checks_metadata = bulk_checks_metadata
        self.only_logs = getattr(arguments, "only_logs", None)
        self.unix_timestamp = getattr(arguments, "unix_timestamp", None)
        self.shodan_api_key = getattr(arguments, "shodan", None)
        self.fixer = getattr(arguments, "fixer", None)

        # Shodan API Key
        if self.shodan_api_key:
            # TODO: revisit this logic
            provider = Provider.get_global_provider()
            updated_audit_config = Provider.update_provider_config(
                provider.audit_config, "shodan_api_key", self.shodan_api_key
            )
            if updated_audit_config:
                provider._audit_config = updated_audit_config

        # Check output directory, if it is not created -> create it
        if self.output_directory and not self.fixer:
            if not isdir(self.output_directory):
                if self.output_modes:
                    makedirs(self.output_directory, exist_ok=True)
            if not isdir(self.output_directory + "/compliance"):
                if self.output_modes:
                    makedirs(self.output_directory + "/compliance", exist_ok=True)


@dataclass
class Connection:
    """
    Represents a test connection object.
    Attributes:
        is_connected (bool): Indicates whether the connection is established or not.
        error (Exception): The exception object if an error occurred during the connection test.
    """

    is_connected: bool = False
    error: Exception = None
