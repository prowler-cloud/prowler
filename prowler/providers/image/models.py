from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


class ImageOutputOptions(ProviderOutputOptions):
    """
    ImageOutputOptions customizes output filename logic for container image scanning.

    Attributes inherited from ProviderOutputOptions:
        - output_filename (str): The base filename used for generated reports.
        - output_directory (str): The directory to store the output files.
    """

    def __init__(self, arguments, bulk_checks_metadata):
        super().__init__(arguments, bulk_checks_metadata)

        # If --output-filename is not specified, build a default name
        if not getattr(arguments, "output_filename", None):
            self.output_filename = f"prowler-output-image-{output_file_timestamp}"
        else:
            self.output_filename = arguments.output_filename
