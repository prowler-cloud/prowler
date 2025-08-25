from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


class LLMOutputOptions(ProviderOutputOptions):
    """
    LLMOutputOptions overrides ProviderOutputOptions for LLM-specific output logic.
    For example, generating a filename that includes the LLM tenant_id.

    Attributes inherited from ProviderOutputOptions:
        - output_filename (str): The base filename used for generated reports.
        - output_directory (str): The directory to store the output files.
        - ... see ProviderOutputOptions for more details.

    Methods:
        - __init__: Customizes the output filename logic for LLM.
    """

    def __init__(self, arguments, bulk_checks_metadata):
        super().__init__(arguments, bulk_checks_metadata)

        # If --output-filename is not specified, build a default name.
        if not getattr(arguments, "output_filename", None):
            self.output_filename = f"prowler-output-llm-{output_file_timestamp}"
        # If --output-filename was explicitly given, respect that
        else:
            self.output_filename = arguments.output_filename
