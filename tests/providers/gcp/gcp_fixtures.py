from uuid import uuid4

from mock import MagicMock

from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.models import GCPIdentityInfo

GCP_PROJECT_ID = "123456789012"


def set_mocked_gcp_provider(
    project_ids: list[str] = [], profile: str = ""
) -> GcpProvider:
    provider = MagicMock()
    provider.type = "gcp"
    provider.session = None
    provider.project_ids = project_ids
    provider.identity = GCPIdentityInfo(
        profile=profile,
    )

    return provider


def mock_api_client(_, __, ___, ____):
    client = MagicMock()

    mock_api_project_calls(client)
    mock_api_dataset_calls(client)
    mock_api_tables_calls(client)

    mock_api_cloudresourcemanager_client(client)
    mock_api_cloudsql_client(client)

    return client


def mock_is_api_active(_, audited_project_ids):
    return audited_project_ids


def mock_api_project_calls(client: MagicMock):
    client.projects().locations().keys().list().execute.return_value = {
        "keys": [
            {
                "displayName": "key1",
                "uid": str(uuid4()),
                "createTime": "2021-01-01T00:00:00Z",
                "restrictions": {},
            },
            {
                "displayName": "key2",
                "uid": str(uuid4()),
                "createTime": "2021-01-01T00:00:00Z",
                "restrictions": {},
            },
        ]
    }
    # Next page is None to not enter in the while infinite loop
    client.projects().locations().keys().list_next.return_value = None
    # Mocking policy
    client.projects().getIamPolicy().execute.return_value = {
        "auditConfigs": [MagicMock()],
        "bindings": [
            {
                "role": "roles/resourcemanager.organizationAdmin",
                "members": [
                    "user:mike@example.com",
                    "group:admins@example.com",
                    "domain:google.com",
                    "serviceAccount:my-project-id@appspot.gserviceaccount.com",
                ],
            },
            {
                "role": "roles/resourcemanager.organizationViewer",
                "members": ["user:eve@example.com"],
                "condition": {
                    "title": "expirable access",
                    "description": "Does not grant access after Sep 2020",
                    "expression": "request.time < timestamp('2020-10-01T00:00:00.000Z')",
                },
            },
        ],
        "etag": "BwWWja0YfJA=",
        "version": 3,
    }


def mock_api_dataset_calls(client: MagicMock):
    # Mocking datasets
    dataset1_id = str(uuid4())
    dataset2_id = str(uuid4())

    client.datasets().list().execute.return_value = {
        "datasets": [
            {
                "datasetReference": {
                    "datasetId": "unique_dataset1_name",
                    "projectId": GCP_PROJECT_ID,
                },
                "id": dataset1_id,
                "location": "US",
            },
            {
                "datasetReference": {
                    "datasetId": "unique_dataset2_name",
                    "projectId": GCP_PROJECT_ID,
                },
                "id": dataset2_id,
                "location": "EU",
            },
        ]
    }

    # Mock two dataset cases get funcion
    def mock_get_dataset(datasetId, projectId=GCP_PROJECT_ID):
        return_value = MagicMock()

        if projectId == GCP_PROJECT_ID:
            if datasetId == "unique_dataset1_name":
                return_value.execute.return_value = {
                    "access": "allAuthenticatedUsers",
                    "defaultEncryptionConfiguration": True,
                }
            elif datasetId == "unique_dataset2_name":
                return_value.execute.return_value = {
                    "access": "nobody",
                    "defaultEncryptionConfiguration": False,
                }

        return return_value

    client.datasets().get = mock_get_dataset
    client.datasets().list_next.return_value = None


def mock_api_tables_calls(client: MagicMock):
    # Mocking related tables to the datasets
    table1_id = str(uuid4())
    table2_id = str(uuid4())

    # Mocking two datasets cases
    def mock_list_tables(datasetId, projectId=GCP_PROJECT_ID):
        return_value = MagicMock()

        if projectId == GCP_PROJECT_ID:
            if (
                datasetId
                == client.datasets()
                .list()
                .execute()["datasets"][0]["datasetReference"]["datasetId"]
            ):
                return_value.execute.return_value = {
                    "tables": [
                        {
                            "tableReference": {"tableId": "unique_table1_name"},
                            "id": table1_id,
                        },
                        {
                            "tableReference": {"tableId": "unique_table2_name"},
                            "id": table2_id,
                        },
                    ]
                }
            elif (
                datasetId
                == client.datasets()
                .list()
                .execute()["datasets"][1]["datasetReference"]["datasetId"]
            ):
                return_value.execute.return_value = {"tables": []}

        return return_value

    client.tables().list = mock_list_tables

    # Mocking the encryption configuration of the tables
    def mock_get_table(projectId, datasetId, tableId):
        return_value = MagicMock()

        if (
            projectId == GCP_PROJECT_ID
            and datasetId
            == client.datasets()
            .list()
            .execute()["datasets"][0]["datasetReference"]["datasetId"]
        ):
            if tableId == "unique_table1_name":
                return_value.execute.return_value = {"encryptionConfiguration": True}
            elif tableId == "unique_table2_name":
                return_value.execute.return_value = {"encryptionConfiguration": False}
        elif (
            projectId == GCP_PROJECT_ID
            and datasetId
            == client.datasets()
            .list()
            .execute()["datasets"][1]["datasetReference"]["datasetId"]
        ):
            return_value.execute.return_value = None

        return return_value

    client.tables().get = mock_get_table
    client.tables().list_next.return_value = None


def mock_api_cloudresourcemanager_client(client: MagicMock):
    # Mocking organizations
    client.organizations().search().execute.return_value = {
        "organizations": [
            {"name": "organizations/123456789", "displayName": "Organization 1"},
            {"name": "organizations/987654321", "displayName": "Organization 2"},
        ]
    }


def mock_api_cloudsql_client(client: MagicMock):
    pass
