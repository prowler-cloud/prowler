import importlib
import sys
from dataclasses import dataclass
from os import makedirs
from os.path import isdir

from prowler.config.config import change_config_var, output_file_timestamp
from prowler.lib.logger import logger


def set_provider_output_options(
    provider: str, arguments, audit_info, mutelist_file, bulk_checks_metadata
):
    """
    set_provider_output_options configures automatically the outputs based on the selected provider and returns the Provider_Output_Options object.
    """
    try:
        # Dynamically load the Provider_Output_Options class
        provider_output_class = f"{provider.capitalize()}_Output_Options"
        provider_output_options = getattr(
            importlib.import_module(__name__), provider_output_class
        )(arguments, audit_info, mutelist_file, bulk_checks_metadata)
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        sys.exit(1)
    else:
        return provider_output_options


@dataclass
class Provider_Output_Options:
    is_quiet: bool
    output_modes: list
    output_directory: str
    mutelist_file: str
    bulk_checks_metadata: dict
    verbose: str
    output_filename: str
    only_logs: bool
    unix_timestamp: bool

    def __init__(self, arguments, mutelist_file, bulk_checks_metadata):
        self.is_quiet = arguments.quiet
        self.output_modes = arguments.output_modes
        self.output_directory = arguments.output_directory
        self.verbose = arguments.verbose
        self.bulk_checks_metadata = bulk_checks_metadata
        self.mutelist_file = mutelist_file
        self.only_logs = arguments.only_logs
        self.unix_timestamp = arguments.unix_timestamp
        # Check output directory, if it is not created -> create it
        if arguments.output_directory:
            if not isdir(arguments.output_directory):
                if arguments.output_modes:
                    makedirs(arguments.output_directory)


class Azure_Output_Options(Provider_Output_Options):
    def __init__(self, arguments, audit_info, mutelist_file, bulk_checks_metadata):
        # First call Provider_Output_Options init
        super().__init__(arguments, mutelist_file, bulk_checks_metadata)

        # Check if custom output filename was input, if not, set the default
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            if (
                audit_info.identity.domain
                != "Unknown tenant domain (missing AAD permissions)"
            ):
                self.output_filename = f"prowler-output-{audit_info.identity.domain}-{output_file_timestamp}"
            else:
                self.output_filename = f"prowler-output-{'-'.join(audit_info.identity.tenant_ids)}-{output_file_timestamp}"
        else:
            self.output_filename = arguments.output_filename


class Gcp_Output_Options(Provider_Output_Options):
    def __init__(self, arguments, audit_info, mutelist_file, bulk_checks_metadata):
        # First call Provider_Output_Options init
        super().__init__(arguments, mutelist_file, bulk_checks_metadata)

        # Check if custom output filename was input, if not, set the default
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            self.output_filename = f"prowler-output-{audit_info.default_project_id}-{output_file_timestamp}"
        else:
            self.output_filename = arguments.output_filename


class Aws_Output_Options(Provider_Output_Options):
    security_hub_enabled: bool

    def __init__(self, arguments, audit_info, mutelist_file, bulk_checks_metadata):
        # First call Provider_Output_Options init
        super().__init__(arguments, mutelist_file, bulk_checks_metadata)

        # Confire Shodan API
        if arguments.shodan:
            audit_info = change_config_var(
                "shodan_api_key", arguments.shodan, audit_info
            )

        # Check if custom output filename was input, if not, set the default
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            self.output_filename = (
                f"prowler-output-{audit_info.audited_account}-{output_file_timestamp}"
            )
        else:
            self.output_filename = arguments.output_filename

        # Security Hub Outputs
        self.security_hub_enabled = arguments.security_hub
        if arguments.security_hub:
            if not self.output_modes:
                self.output_modes = ["json-asff"]
            else:
                self.output_modes.append("json-asff")
