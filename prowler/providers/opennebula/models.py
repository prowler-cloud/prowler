from dataclasses import dataclass
from pyone import OneServer
from prowler.providers.common.models import ProviderOutputOptions
from prowler.config.config import output_file_timestamp

@dataclass
class OpenNebulaSession:
    """Class to hold the OpenNebula session information"""
    client: OneServer 
    endpoint: str
    username: str
    auth_token: str

@dataclass
class OpenNebulaIdentity:
    """Class to hold the OpenNebula identity information"""
    user_id: str
    user_name: str
    group_id: str
    group_name: str


class OpenNebulaOutputOptions(ProviderOutputOptions):
    def __init__(self, arguments, bulk_checks_metadata, identity):
        # First call ProviderOutputOptions init
        super().__init__(arguments, bulk_checks_metadata)
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            self.output_filename = f"prowler-output-{identity.user_name}-{output_file_timestamp}"
        else:
            self.output_filename = arguments.output_filename