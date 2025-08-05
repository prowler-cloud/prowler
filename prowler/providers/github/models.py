from pydantic.v1 import BaseModel

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


class GithubSession(BaseModel):
    token: str
    key: str
    id: str


class GithubIdentityInfo(BaseModel):
    account_id: str
    account_name: str
    account_url: str


class GithubAppIdentityInfo(BaseModel):
    app_id: str


class GithubOutputOptions(ProviderOutputOptions):
    def __init__(self, arguments, bulk_checks_metadata, identity):
        # First call ProviderOutputOptions init
        super().__init__(arguments, bulk_checks_metadata)
        # TODO move the below if to ProviderOutputOptions
        # Check if custom output filename was input, if not, set the default
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            if isinstance(identity, GithubIdentityInfo):
                self.output_filename = (
                    f"prowler-output-{identity.account_name}-{output_file_timestamp}"
                )
            elif isinstance(identity, GithubAppIdentityInfo):
                self.output_filename = (
                    f"prowler-output-{identity.app_id}-{output_file_timestamp}"
                )
        else:
            self.output_filename = arguments.output_filename
