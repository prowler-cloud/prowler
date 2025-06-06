from argparse import Namespace
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import ionoscloud

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions
from ionoscloud.models.datacenters import Datacenters

@dataclass
class IonosIdentityInfo:
    username: str
    password: str
    datacenter_id: str
    token: str

class IonosOutputOptions(ProviderOutputOptions):
    """
    Output options for ionos provider
    """

    security_hub_enabled: bool

    def __init__(self, arguments, bulk_checks_metadata, identity):
        super().__init__(arguments, bulk_checks_metadata)

        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            token_prefix = identity.token[:12] if identity.token else ""
            self.output_filename = (
                f"prowler-output-{token_prefix}-{output_file_timestamp}"
            )
        else:
            self.output_filename = arguments.output_filename