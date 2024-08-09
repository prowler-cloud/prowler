from dataclasses import dataclass
from os import makedirs
from os.path import isdir

from pydantic import BaseModel

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
        self.status = arguments.status
        self.output_modes = arguments.output_formats
        self.output_directory = arguments.output_directory
        self.verbose = arguments.verbose
        self.bulk_checks_metadata = bulk_checks_metadata
        self.only_logs = arguments.only_logs
        self.unix_timestamp = arguments.unix_timestamp
        self.shodan_api_key = arguments.shodan
        self.fixer = getattr(arguments, "fixer", None)

        # Shodan API Key
        if arguments.shodan:
            # TODO: revisit this logic
            provider = Provider.get_global_provider()
            updated_audit_config = Provider.update_provider_config(
                provider.audit_config, "shodan_api_key", arguments.shodan
            )
            if updated_audit_config:
                provider._audit_config = updated_audit_config

        # Check output directory, if it is not created -> create it
        if arguments.output_directory and not self.fixer:
            if not isdir(arguments.output_directory):
                if arguments.output_formats:
                    makedirs(arguments.output_directory, exist_ok=True)
            if not isdir(arguments.output_directory + "/compliance"):
                if arguments.output_formats:
                    makedirs(arguments.output_directory + "/compliance", exist_ok=True)


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
