"""MongoDB Atlas Test Fixtures"""

from mock import MagicMock

from prowler.providers.mongodbatlas.models import (
    MongoDBAtlasIdentityInfo,
    MongoDBAtlasSession,
)
from prowler.providers.mongodbatlas.mongodbatlas_provider import MongodbatlasProvider

# Test credentials
ATLAS_PUBLIC_KEY = "test_public_key"
ATLAS_PRIVATE_KEY = "test_private_key"
ATLAS_BASE_URL = "https://cloud.mongodb.com/api/atlas/v2"

# Test user identity
USER_ID = "test_public_key"
USERNAME = "api-key-test_pub"

# Test project
PROJECT_ID = "test_project_id"
PROJECT_NAME = "test_project"
ORG_ID = "test_org_id"

# Test cluster
CLUSTER_ID = "test_cluster_id"
CLUSTER_NAME = "test_cluster"
CLUSTER_TYPE = "REPLICASET"
MONGO_VERSION = "7.0"
STATE_NAME = "IDLE"

# Test network access entries
NETWORK_ACCESS_ENTRY_OPEN = {"cidrBlock": "0.0.0.0/0", "comment": "Open to world"}

NETWORK_ACCESS_ENTRY_RESTRICTED = {
    "cidrBlock": "10.0.0.0/8",
    "comment": "Private network",
}

# Mock API responses
MOCK_ORGS_RESPONSE = {
    "results": [
        {
            "id": ORG_ID,
            "name": "Test Organization",
            "isDeleted": False,
        }
    ],
    "totalCount": 1,
}

MOCK_PROJECT_RESPONSE = {
    "id": PROJECT_ID,
    "name": PROJECT_NAME,
    "orgId": ORG_ID,
    "created": "2024-01-01T00:00:00Z",
    "clusterCount": 1,
}

MOCK_CLUSTER_RESPONSE = {
    "id": CLUSTER_ID,
    "name": CLUSTER_NAME,
    "clusterType": CLUSTER_TYPE,
    "mongoDBVersion": MONGO_VERSION,
    "stateName": STATE_NAME,
    "encryptionAtRestProvider": "AWS",
    "backupEnabled": True,
    "providerSettings": {
        "providerName": "AWS",
        "regionName": "US_EAST_1",
        "encryptEBSVolume": True,
    },
}

MOCK_NETWORK_ACCESS_RESPONSE = {
    "results": [NETWORK_ACCESS_ENTRY_OPEN, NETWORK_ACCESS_ENTRY_RESTRICTED],
    "totalCount": 2,
}

MOCK_PAGINATED_PROJECTS_RESPONSE = {"results": [MOCK_PROJECT_RESPONSE], "totalCount": 1}

MOCK_PAGINATED_CLUSTERS_RESPONSE = {"results": [MOCK_CLUSTER_RESPONSE], "totalCount": 1}


# Mocked MongoDB Atlas Provider
def set_mocked_mongodbatlas_provider(
    session: MongoDBAtlasSession = MongoDBAtlasSession(
        public_key=ATLAS_PUBLIC_KEY,
        private_key=ATLAS_PRIVATE_KEY,
        base_url=ATLAS_BASE_URL,
    ),
    identity: MongoDBAtlasIdentityInfo = MongoDBAtlasIdentityInfo(
        user_id=USER_ID,
        username=USERNAME,
        roles=["API_KEY"],
    ),
    audit_config: dict = None,
    organization_id: str = None,
    project_id: str = None,
) -> MongodbatlasProvider:

    provider = MagicMock()
    provider.type = "mongodbatlas"
    provider.session = session
    provider.identity = identity
    provider.audit_config = audit_config
    provider.organization_id = organization_id
    provider.project_id = project_id

    return provider
