from typing import List, Optional

from pydantic.v1 import BaseModel

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


class MongoDBAtlasSession(BaseModel):
    """MongoDB Atlas session model"""

    public_key: str
    private_key: str
    base_url: str = "https://cloud.mongodb.com/api/atlas/v2"


class MongoDBAtlasIdentityInfo(BaseModel):
    """MongoDB Atlas identity information model"""

    organization_id: str
    organization_name: str
    roles: Optional[List[str]] = []


class MongoDBAtlasOutputOptions(ProviderOutputOptions):
    """MongoDB Atlas output options"""

    def __init__(self, arguments, bulk_checks_metadata, identity):
        super().__init__(arguments, bulk_checks_metadata)

        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            self.output_filename = (
                f"prowler-output-{identity.organization_id}-{output_file_timestamp}"
            )
        else:
            self.output_filename = arguments.output_filename
