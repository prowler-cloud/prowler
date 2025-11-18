from pydantic.v1 import BaseModel

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


class StackITIdentityInfo(BaseModel):
    """
    StackITIdentityInfo holds basic identity fields for the StackIT provider.

    Attributes:
        - project_id (str): The StackIT project ID being audited.
        - project_name (str): The name of the StackIT project (fetched from Resource Manager API).
    """

    project_id: str
    project_name: str = ""


class StackITOutputOptions(ProviderOutputOptions):
    """
    StackITOutputOptions overrides ProviderOutputOptions for StackIT-specific output logic.
    Generates a filename that includes the StackIT project_id.

    Attributes inherited from ProviderOutputOptions:
        - output_filename (str): The base filename used for generated reports.
        - output_directory (str): The directory to store the output files.
        - ... see ProviderOutputOptions for more details.

    Methods:
        - __init__: Customizes the output filename logic for StackIT.
    """

    def __init__(self, arguments, bulk_checks_metadata, identity: StackITIdentityInfo):
        super().__init__(arguments, bulk_checks_metadata)

        # If --output-filename is not specified, build a default name.
        if not getattr(arguments, "output_filename", None):
            # If project_id exists, include it in the filename (e.g., prowler-output-stackit-<project_id>-20230101)
            if identity.project_id:
                self.output_filename = (
                    f"prowler-output-stackit-{identity.project_id}-{output_file_timestamp}"
                )
            # Otherwise just 'prowler-output-stackit-<timestamp>'
            else:
                self.output_filename = f"prowler-output-stackit-{output_file_timestamp}"
        # If --output-filename was explicitly given, respect that
        else:
            self.output_filename = arguments.output_filename
