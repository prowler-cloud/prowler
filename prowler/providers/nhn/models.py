from pydantic import BaseModel
from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions

class NHNIdentityInfo(BaseModel):
    """
    NHNIdentityInfo holds basic identity fields for the NHN provider.

    Attributes:
        - identity_id (str): An optional identity ID if used by NHN services.
        - identity_type (str): The type or role of the identity, if needed.
        - tenant_id (str): The tenant ID for the NHN Cloud account.
        - tenant_domain (str): The tenant domain if applicable. 
          (Some NHN services might require a domain or project domain.)
    """
    identity_id: str = ""
    identity_type: str = ""
    tenant_id: str = ""
    tenant_domain: str = ""

class NHNOutputOptions(ProviderOutputOptions):
    """
    NHNOutputOptions overrides ProviderOutputOptions for NHN-specific output logic.
    For example, generating a filename that includes the NHN tenant_id.

    Attributes inherited from ProviderOutputOptions:
        - output_filename (str): The base filename used for generated reports.
        - output_directory (str): The directory to store the output files.
        - ... see ProviderOutputOptions for more details.

    Methods:
        - __init__: Customizes the output filename logic for NHN.
    """
    def __init__(self, arguments, bulk_checks_metadata, identity: NHNIdentityInfo):
        super().__init__(arguments, bulk_checks_metadata)

        # If --output-filename is not specified, build a default name.
        if not getattr(arguments, "output_filename", None):
            # If tenant_id exists, include it in the filename (e.g., prowler-output-nhn-<tenant_id>-20230101)
            if identity.tenant_id:
                self.output_filename = (
                    f"prowler-output-nhn-{identity.tenant_id}-{output_file_timestamp}"
                )
            # Otherwise just 'prowler-output-nhn-<timestamp>'
            else:
                self.output_filename = (
                    f"prowler-output-nhn-{output_file_timestamp}"
                )
        # If --output-filename was explicitly given, respect that
        else:
            self.output_filename = arguments.output_filename
