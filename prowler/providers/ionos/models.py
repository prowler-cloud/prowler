from argparse import Namespace
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions

class IonosOutputOptions(ProviderOutputOptions):
    """
    Output options for ionos provider
    """

    security_hub_enabled: bool

    def __init__(self, arguments, bulk_checks_metadata, identity):
        # First call Provider_Output_Options init
        super().__init__(arguments, bulk_checks_metadata)

        # Check if custom output filename was input, if not, set the default
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            self.output_filename = (
                f"prowler-output-{identity}-{output_file_timestamp}"
            )
        else:
            self.output_filename = arguments.output_filename