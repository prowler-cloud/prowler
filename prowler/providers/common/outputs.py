import importlib
import sys
from dataclasses import dataclass
from os import mkdir
from os.path import isdir

from prowler.config.config import change_config_var, output_file_timestamp
from prowler.lib.logger import logger


def set_provider_output_options(
    provider: str, arguments, audit_info, allowlist_file, bulk_checks_metadata
):
    """
    set_provider_output_options configures automatically the outputs based on the selected provider and returns the Provider_Output_Options object.
    """
    try:
        # Dynamically load the Provider_Output_Options class
        provider_output_class = f"{provider.capitalize()}_Output_Options"
        provider_output_options = getattr(
            importlib.import_module(__name__), provider_output_class
        )(arguments, audit_info, allowlist_file, bulk_checks_metadata)
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        sys.exit()
    else:
        return provider_output_options


@dataclass
class Provider_Output_Options:
    is_quiet: bool
    output_modes: list
    output_directory: str
    allowlist_file: str
    bulk_checks_metadata: dict
    verbose: str
    output_filename: str
    only_logs: bool

    def __init__(self, arguments, allowlist_file, bulk_checks_metadata):
        self.is_quiet = arguments.quiet
        self.output_modes = arguments.output_modes
        self.output_directory = arguments.output_directory
        self.verbose = arguments.verbose
        self.bulk_checks_metadata = bulk_checks_metadata
        self.allowlist_file = allowlist_file
        self.only_logs = arguments.only_logs
        # Check output directory, if it is not created -> create it
        if arguments.output_directory:
            if not isdir(arguments.output_directory):
                if arguments.output_modes:
                    mkdir(arguments.output_directory)


class Azure_Output_Options(Provider_Output_Options):
    def __init__(self, arguments, audit_info, allowlist_file, bulk_checks_metadata):
        # First call Provider_Output_Options init
        super().__init__(arguments, allowlist_file, bulk_checks_metadata)

        # Check if custom output filename was input, if not, set the default
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            if audit_info.identity.domain:
                self.output_filename = f"prowler-output-{audit_info.identity.domain}-{output_file_timestamp}"
            else:
                self.output_filename = f"prowler-output-{'-'.join(audit_info.identity.tenant_ids)}-{output_file_timestamp}"
        else:
            self.output_filename = arguments.output_filename

        # Remove HTML Output since it is not supported yet
        if "html" in arguments.output_modes:
            arguments.output_modes.remove("html")


class Aws_Output_Options(Provider_Output_Options):
    security_hub_enabled: bool

    def __init__(self, arguments, audit_info, allowlist_file, bulk_checks_metadata):
        # First call Provider_Output_Options init
        super().__init__(arguments, allowlist_file, bulk_checks_metadata)

        # Confire Shodan API
        if arguments.shodan:
            change_config_var("shodan_api_key", arguments.shodan)

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
