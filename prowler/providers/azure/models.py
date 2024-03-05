from pydantic import BaseModel

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


class AzureIdentityInfo(BaseModel):
    identity_id: str = ""
    identity_type: str = ""
    tenant_ids: list[str] = []
    domain: str = "Unknown tenant domain (missing AAD permissions)"
    subscriptions: dict = {}
    locations: dict = {}


class AzureRegionConfig(BaseModel):
    name: str = ""
    authority: str = None
    base_url: str = ""
    credential_scopes: list = []


class AzureOutputOptions(ProviderOutputOptions):
    def __init__(self, arguments, bulk_checks_metadata, identity):
        # First call Provider_Output_Options init
        super().__init__(arguments, bulk_checks_metadata)

        # Confire Shodan API
        # TODO: review shodan for the new AWS provider
        # if arguments.shodan:
        #     audit_info = change_config_var(
        #         "shodan_api_key", arguments.shodan, audit_info
        #     )

        # Check if custom output filename was input, if not, set the default
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            if identity.domain != "Unknown tenant domain (missing AAD permissions)":
                self.output_filename = (
                    f"prowler-output-{identity.domain}-{output_file_timestamp}"
                )
            else:
                self.output_filename = f"prowler-output-{'-'.join(identity.tenant_ids)}-{output_file_timestamp}"
        else:
            self.output_filename = arguments.output_filename
