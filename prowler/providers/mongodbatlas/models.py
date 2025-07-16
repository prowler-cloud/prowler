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

    user_id: str
    username: str
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
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
                f"prowler-output-{identity.username}-{output_file_timestamp}"
            )
        else:
            self.output_filename = arguments.output_filename


class MongoDBAtlasProject(BaseModel):
    """MongoDB Atlas project model"""

    id: str
    name: str
    org_id: str
    created: str
    cluster_count: int
    project_settings: Optional[dict] = {}


class MongoDBAtlasCluster(BaseModel):
    """MongoDB Atlas cluster model"""

    id: str
    name: str
    project_id: str
    mongo_db_version: str
    cluster_type: str
    state_name: str
    encryption_at_rest_provider: Optional[str] = None
    backup_enabled: bool = False
    bi_connector: Optional[dict] = {}
    provider_settings: Optional[dict] = {}
    replication_specs: Optional[List[dict]] = []


class MongoDBAtlasNetworkAccessEntry(BaseModel):
    """MongoDB Atlas network access entry model"""

    cidr_block: Optional[str] = None
    ip_address: Optional[str] = None
    aws_security_group: Optional[str] = None
    comment: Optional[str] = None
    delete_after_date: Optional[str] = None
