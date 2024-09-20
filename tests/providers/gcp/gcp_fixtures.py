from uuid import uuid4

from mock import MagicMock

from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.models import GCPIdentityInfo

GCP_PROJECT_ID = "123456789012"

GCP_EU1_LOCATION = "europe-west1"
GCP_US_CENTER1_LOCATION = "us-central1"


def set_mocked_gcp_provider(
    project_ids: list[str] = [GCP_PROJECT_ID], profile: str = ""
) -> GcpProvider:
    provider = MagicMock()
    provider.type = "gcp"
    provider.session = MagicMock()
    provider.session._service_account_email = "test@test.com"
    provider.project_ids = project_ids
    provider.default_project_id = GCP_PROJECT_ID
    provider.identity = GCPIdentityInfo(
        profile=profile,
    )

    return provider


def mock_api_client(GCPService, service, api_version, _):
    client = MagicMock()

    mock_api_projects_calls(client)
    mock_api_dataset_calls(client)
    mock_api_tables_calls(client)
    mock_api_organizations_calls(client)
    mock_api_instances_calls(client, service)
    mock_api_buckets_calls(client)
    mock_api_regions_calls(client)
    mock_api_zones_calls(client)
    mock_api_networks_calls(client)
    mock_api_subnetworks_calls(client)
    mock_api_addresses_calls(client)
    mock_api_firewall_calls(client)
    mock_api_urlMaps_calls(client)
    mock_api_managedZones_calls(client)
    mock_api_policies_calls(client)
    mock_api_sink_calls(client)
    mock_api_services_calls(client)

    return client


def mock_is_api_active(_, audited_project_ids):
    return audited_project_ids


def mock_api_projects_calls(client: MagicMock):
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
    # Used by compute client
    client.projects().get().execute.return_value = {
        "commonInstanceMetadata": {
            "items": [
                {
                    "key": "enable-oslogin",
                    "value": "TRUE",
                },
                {
                    "key": "enable-oslogin",
                    "value": "FALSE",
                },
                {
                    "key": "testing-key",
                    "value": "TRUE",
                },
            ]
        }
    }
    client.projects().list_next.return_value = None
    # Used by dataproc client

    cluster1_id = str(uuid4())
    cluster2_id = str(uuid4())

    if client.projects().regions().clusters.__class__.__name__ == "dict":
        client.projects().regions().clusters = MagicMock()

    client.projects().regions().clusters().list().execute.return_value = {
        "clusters": [
            {
                "clusterName": "cluster1",
                "clusterUuid": cluster1_id,
                "config": {
                    "encryptionConfig": {
                        "gcePdKmsKeyName": "projects/123/locations/456/keyRings/789/cryptoKeys/123"
                    }
                },
            },
            {
                "clusterName": "cluster2",
                "clusterUuid": cluster2_id,
                "config": {"encryptionConfig": {}},
            },
        ]
    }
    client.projects().regions().clusters().list_next.return_value = None
    # Used by gke client
    client.projects().locations().list().execute.return_value = {
        "locations": [{"name": "eu-west1"}]
    }
    client.projects().locations().list_next.return_value = None

    if client.projects().locations().clusters.__class__.__name__ == "dict":
        client.projects().locations().clusters = MagicMock()

    client.projects().locations().clusters().list().execute.return_value = {
        "clusters": [
            {
                "name": "cluster1",
                "id": "cluster1_id",
                "location": "eu-west1",
                "nodeConfig": {"serviceAccount": "service_account1"},
                "nodePools": [
                    {
                        "name": "node_pool1",
                        "locations": ["cluster1_location1"],
                        "config": {"serviceAccount": "service_account1"},
                    }
                ],
            },
            {
                "name": "cluster2",
                "id": "cluster2_id",
                "location": "eu-west1",
                "nodeConfig": {"serviceAccount": "service_account2"},
                "nodePools": [
                    {
                        "name": "node_pool2",
                        "locations": ["cluster2_location1"],
                        "config": {"serviceAccount": "service_account2"},
                    },
                    {
                        "name": "node_pool3",
                        "locations": ["cluster2_location2"],
                        "config": {"serviceAccount": "service_account3"},
                    },
                ],
            },
        ]
    }
    # Used by KMS
    client.projects().locations().keyRings().list().execute.return_value = {
        "keyRings": [
            {
                "name": "projects/123/locations/eu-west1/keyRings/keyring1",
                "createTime": "2021-01-01T00:00:00Z",
            },
            {
                "name": "projects/123/locations/eu-west1/keyRings/keyring2",
                "createTime": "2021-01-01T00:00:00Z",
            },
        ]
    }
    client.projects().locations().keyRings().list_next.return_value = None

    def mock_list_crypto_keys(parent):
        return_value = MagicMock()
        if parent == "projects/123/locations/eu-west1/keyRings/keyring1":
            return_value.execute.return_value = {
                "cryptoKeys": [
                    {
                        "name": "projects/123/locations/eu-west1/keyRings/keyring1/cryptoKeys/key1",
                        "createTime": "2021-01-01T00:00:00Z",
                        "rotationPeriod": "7776000s",
                    },
                    {
                        "name": "projects/123/locations/eu-west1/keyRings/keyring2/cryptoKeys/key2",
                        "createTime": "2021-01-01T00:00:00Z",
                    },
                ]
            }
        elif parent == "projects/123/locations/eu-west1/keyRings/keyring2":
            return_value.execute.return_value = {"cryptoKeys": []}
        return return_value

    client.projects().locations().keyRings().cryptoKeys().list = mock_list_crypto_keys

    client.projects().locations().keyRings().cryptoKeys().list_next.return_value = None

    def mock_get_crypto_keys_iam_policy(resource):
        return_value = MagicMock()
        if (
            resource
            == "projects/123/locations/eu-west1/keyRings/keyring1/cryptoKeys/key1"
        ):
            return_value.execute.return_value = {
                "auditConfigs": [MagicMock()],
                "bindings": [
                    {
                        "role": "roles/resourcemanager.organizationAdmin",
                        "members": [
                            "user:mike@example.com",
                            "group:admins@example.com",
                        ],
                    },
                    {
                        "role": "roles/resourcemanager.organizationViewer",
                        "members": [
                            "domain:google.com",
                            "serviceAccount:my-project-id@appspot.gserviceaccount.com",
                        ],
                        "condition": {
                            "title": "expirable access",
                            "description": "Does not grant access after Sep 2020",
                            "expression": "request.time < timestamp('2020-10-01T00:00:00.000Z')",
                        },
                    },
                ],
            }
        elif (
            resource
            == "projects/123/locations/eu-west1/keyRings/keyring2/cryptoKeys/key2"
        ):
            return_value.execute.return_value = {
                "auditConfigs": [MagicMock()],
                "bindings": [
                    {
                        "role": "roles/resourcemanager.organizationAdmin",
                        "members": ["user:mike@example.com"],
                    },
                    {
                        "role": "roles/resourcemanager.organizationViewer",
                        "members": ["group:admins@example.com"],
                        "condition": {
                            "title": "expirable access",
                            "description": "Does not grant access after Sep 2020",
                            "expression": "request.time < timestamp('2020-10-01T00:00:00.000Z')",
                        },
                    },
                ],
            }
        return return_value

    client.projects().locations().keyRings().cryptoKeys().getIamPolicy = (
        mock_get_crypto_keys_iam_policy
    )
    # Used by logging
    client.projects().metrics().list().execute.return_value = {
        "metrics": [
            {
                "name": "metric1",
                "filter": "resource.type=gae_app AND severity>=ERROR",
                "metricDescriptor": {
                    "name": "projects/123/metricDescriptors/custom.googleapis.com/invoice/paid/amount",
                    "type": "custom.googleapis.com/invoice/paid/amount",
                },
            },
            {
                "name": "metric2",
                "metricDescriptor": {
                    "name": "projects/123/metricDescriptors/custom.googleapis.com/invoice/paid/amount",
                    "type": "external.googleapis.com/prometheus/up",
                },
                "filter": "resource.type=gae_app AND severity>=ERROR",
            },
        ]
    }
    client.projects().metrics().list_next.return_value = None
    # Used by monitoring
    client.projects().alertPolicies().list().execute.return_value = {
        "alertPolicies": [
            {
                "name": "alert_policy1",
                "displayName": "Alert Policy 1",
                "conditions": [
                    {
                        "conditionThreshold": {
                            "filter": 'metric.type="compute.googleapis.com/instance/disk/write_bytes_count"',
                            "comparison": "COMPARISON_GT",
                            "thresholdValue": 1000,
                        }
                    }
                ],
                "enabled": True,
            },
            {
                "name": "alert_policy2",
                "displayName": "Alert Policy 2",
                "conditions": [
                    {
                        "conditionThreshold": {
                            "filter": 'metric.type="compute.googleapis.com/instance/disk/write_bytes_count"',
                            "comparison": "COMPARISON_GT",
                            "thresholdValue": 2000,
                        }
                    }
                ],
                "enabled": False,
            },
        ]
    }
    client.projects().alertPolicies().list_next.return_value = None
    # Used by IAM
    client.projects().serviceAccounts().list().execute.return_value = {
        "accounts": [
            {
                "name": f"projects/{GCP_PROJECT_ID}/serviceAccounts/service-account1@{GCP_PROJECT_ID}.iam.gserviceaccount.com",
                "email": "service-account1@gmail.com",
                "displayName": "Service Account 1",
            },
            {
                "name": f"projects/{GCP_PROJECT_ID}/serviceAccounts/service-account2@{GCP_PROJECT_ID}.iam.gserviceaccount.com",
                "email": "service-account2@gmail.com",
                "displayName": "Service Account 2",
            },
        ]
    }
    client.projects().serviceAccounts().list_next.return_value = None

    def mock_list_service_accounts_keys(name):
        return_value = MagicMock()
        if (
            name
            == f"projects/{GCP_PROJECT_ID}/serviceAccounts/service-account1@gmail.com"
        ):
            return_value.execute.return_value = {
                "keys": [
                    {
                        "name": "projects/{GCP_PROJECT_ID}/serviceAccounts/service-account1@{GCP_PROJECT_ID}.iam.gserviceaccount.com/keys/key1",
                        "validAfterTime": "2021-01-01T00:00:00Z",
                        "validBeforeTime": "2022-01-01T00:00:00Z",
                        "keyOrigin": "GOOGLE_PROVIDED",
                        "keyType": "SYSTEM_MANAGED",
                    },
                    {
                        "name": "projects/{GCP_PROJECT_ID}/serviceAccounts/service-account1@{GCP_PROJECT_ID}.iam.gserviceaccount.com/keys/key2",
                        "validAfterTime": "2021-01-01T00:00:00Z",
                        "validBeforeTime": "2022-01-01T00:00:00Z",
                        "keyOrigin": "ORIGIN_UNSPECIFIED",
                        "keyType": "USER_MANAGED",
                    },
                ]
            }
        elif (
            name
            == f"projects/{GCP_PROJECT_ID}/serviceAccounts/service-account2@gmail.com"
        ):
            return_value.execute.return_value = {
                "keys": [
                    {
                        "name": "projects/{GCP_PROJECT_ID}/serviceAccounts/service-account2@{GCP_PROJECT_ID}.iam.gserviceaccount.com/keys/key3",
                        "validAfterTime": "2021-01-01T00:00:00Z",
                        "validBeforeTime": "2022-01-01T00:00:00Z",
                        "keyOrigin": "USER_PROVIDED",
                        "keyType": "KEY_TYPE_UNSPECIFIED",
                    },
                ]
            }
        return return_value

    client.projects().serviceAccounts().keys().list = mock_list_service_accounts_keys

    client.projects().getAccessApprovalSettings().execute.return_value = {
        "name": "projects/123/accessApprovalSettings",
        "enrolledAncestor": True,
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


def mock_api_organizations_calls(client: MagicMock):
    client.organizations().search().execute.return_value = {
        "organizations": [
            {
                "name": "organizations/123456789",
                "displayName": "Organization 1",
                "state": "ACTIVE",
                "createTime": "2021-01-01T00:00:00Z",
                "updateTime": "2021-01-01T00:00:00Z",
                "deleteTime": "2021-01-01T00:00:00Z",
                "etag": "",
            },
            {
                "name": "organizations/987654321",
                "displayName": "Organization 2",
                "state": "DELETE_REQUESTED",
                "createTime": "2021-01-01T00:00:00Z",
                "updateTime": "2021-01-01T00:00:00Z",
                "deleteTime": "2021-01-01T00:00:00Z",
                "etag": "",
            },
        ]
    }

    def mock_contact_organization_list(parent):
        return_value = MagicMock()
        if parent == "organizations/123456789":
            return_value.execute.return_value = {
                "contacts": [
                    {
                        "name": "contacts/1",
                        "email": "contact1@example.es",
                    },
                    {"name": "contacts/2", "email": "contact2@example.es"},
                ]
            }
        elif parent == "organizations/987654321":
            return_value.execute.return_value = {"contacts": []}
        return return_value

    client.organizations().contacts().list = mock_contact_organization_list


def mock_api_instances_calls(client: MagicMock, service: str):
    instance1_id = str(uuid4())
    instance2_id = str(uuid4())
    if service == "sqladmin":
        client.instances().list().execute.return_value = {
            "items": [
                {
                    "name": "instance1",
                    "databaseVersion": "MYSQL_5_7",
                    "region": "us-central1",
                    "ipAddresses": [{"type": "PRIMARY", "ipAddress": "66.66.66.66"}],
                    "settings": {
                        "ipConfiguration": {
                            "requireSsl": True,
                            "sslMode": "ENCRYPTED_ONLY",
                            "authorizedNetworks": [{"value": "test"}],
                        },
                        "backupConfiguration": {"enabled": True},
                        "databaseFlags": [],
                    },
                },
                {
                    "name": "instance2",
                    "databaseVersion": "POSTGRES_9_6",
                    "region": "us-central1",
                    "ipAddresses": [{"type": "PRIMARY", "ipAddress": "22.22.22.22"}],
                    "settings": {
                        "ipConfiguration": {
                            "requireSsl": False,
                            "sslMode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED",
                            "authorizedNetworks": [{"value": "test"}],
                        },
                        "backupConfiguration": {"enabled": False},
                        "databaseFlags": [],
                    },
                },
            ]
        }
    elif service == "compute":
        client.instances().list().execute.return_value = {
            "items": [
                {
                    "name": "instance1",
                    "id": instance1_id,
                    "metadata": {},
                    "networkInterfaces": [
                        {
                            "accessConfigs": [
                                {
                                    "natIP": "nat_ip",
                                    "type": "ONE_TO_ONE_NAT",
                                }
                            ],
                        }
                    ],
                    "shieldedInstanceConfig": {
                        "enableVtpm": True,
                        "enableIntegrityMonitoring": True,
                    },
                    "confidentialInstanceConfig": {"enableConfidentialCompute": True},
                    "serviceAccounts": [
                        {
                            "email": "test@test.es",
                            "scopes": ["scope1", "scope2"],
                        }
                    ],
                    "canIpForward": True,
                    "disks": [
                        {
                            "deviceName": "disk1",
                            "diskEncryptionKey": {"sha256": "sha256_key"},
                            "diskSizeGb": 10,
                            "diskType": "disk_type",
                        }
                    ],
                },
                {
                    "name": "instance2",
                    "id": instance2_id,
                    "metadata": {},
                    "networkInterfaces": [],
                    "shieldedInstanceConfig": {
                        "enableVtpm": False,
                        "enableIntegrityMonitoring": False,
                    },
                    "confidentialInstanceConfig": {"enableConfidentialCompute": False},
                    "serviceAccounts": [
                        {
                            "email": "test2@test.es",
                            "scopes": ["scope3"],
                        }
                    ],
                    "canIpForward": False,
                    "disks": [
                        {
                            "deviceName": "disk2",
                            "diskEncryptionKey": {"kmsKeyName": "kms_key"},
                            "diskSizeGb": 20,
                            "diskType": "disk_type",
                        }
                    ],
                },
            ]
        }

    client.instances().list_next.return_value = None


def mock_api_buckets_calls(client: MagicMock):
    bucket1_id = str(uuid4())
    bucket2_id = str(uuid4())

    client.buckets().list().execute.return_value = {
        "items": [
            {
                "name": "bucket1",
                "id": bucket1_id,
                "location": "US",
                "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}},
                "retentionPolicy": {"retentionPeriod": 10},
            },
            {
                "name": "bucket2",
                "id": bucket2_id,
                "location": "EU",
                "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": False}},
                "retentionPolicy": None,
            },
        ]
    }

    def mock_get_buckets_iam_policy(bucket):
        return_value = MagicMock()
        if bucket == bucket1_id:
            return_value.execute.return_value = {"bindings": "allAuthenticatedUsers"}
        elif bucket == bucket2_id:
            return_value.execute.return_value = {"bindings": "nobody"}
        return return_value

    client.buckets().getIamPolicy = mock_get_buckets_iam_policy

    client.buckets().list_next.return_value = None


def mock_api_regions_calls(client: MagicMock):
    region1_id = str(uuid4())

    client.regions().list().execute.return_value = {
        "items": [
            {
                "name": "europe-west1-b",
                "id": region1_id,
            }
        ]
    }
    client.regions().list_next.return_value = None


def mock_api_zones_calls(client: MagicMock):
    zone1_id = str(uuid4())

    client.zones().list().execute.return_value = {
        "items": [
            {
                "name": "zone1",
                "id": zone1_id,
            }
        ]
    }
    client.zones().list_next.return_value = None


def mock_api_networks_calls(client: MagicMock):
    network1_id = str(uuid4())
    network2_id = str(uuid4())
    network3_id = str(uuid4())

    client.networks().list().execute.return_value = {
        "items": [
            {
                "name": "network1",
                "id": network1_id,
                "autoCreateSubnetworks": True,
            },
            {
                "name": "network2",
                "id": network2_id,
                "autoCreateSubnetworks": False,
            },
            {"name": "network3", "id": network3_id},
        ]
    }
    client.networks().list_next.return_value = None


def mock_api_subnetworks_calls(client: MagicMock):
    subnetwork1_id = str(uuid4())
    subnetwork2_id = str(uuid4())
    subnetwork3_id = str(uuid4())

    client.subnetworks().list().execute.return_value = {
        "items": [
            {
                "name": "subnetwork1",
                "id": subnetwork1_id,
                "enableFlowLogs": True,
                "network": "region1/network1",
            },
            {
                "name": "subnetwork2",
                "id": subnetwork2_id,
                "enableFlowLogs": False,
                "network": "region1/network1",
            },
            {
                "name": "subnetwork3",
                "id": subnetwork3_id,
                "enableFlowLogs": False,
                "network": "region2/network3",
            },
        ]
    }
    client.subnetworks().list_next.return_value = None


def mock_api_addresses_calls(client: MagicMock):
    address1_id = str(uuid4())
    address2_id = str(uuid4())
    address3_id = str(uuid4())

    client.addresses().list().execute.return_value = {
        "items": [
            {
                "name": "address1",
                "id": address1_id,
                "address": "10.0.0.1",
                "addressType": "INTERNAL",
            },
            {
                "name": "address2",
                "id": address2_id,
                "address": "10.0.0.2",
                "addressType": "INTERNAL",
            },
            {
                "name": "address3",
                "id": address3_id,
                "address": "20.34.105.200",
                "addressType": "EXTERNAL",
            },
        ]
    }
    client.addresses().list_next.return_value = None


def mock_api_firewall_calls(client: MagicMock):
    firewall1_id = str(uuid4())
    firewall2_id = str(uuid4())
    firewall3_id = str(uuid4())

    client.firewalls().list().execute.return_value = {
        "items": [
            {
                "name": "firewall1",
                "id": firewall1_id,
                "allowed": [{"IPProtocol": "UDP"}],
                "sourceRanges": ["30.0.0.0/16"],
                "direction": "INGRESS",
            },
            {
                "name": "firewall2",
                "id": firewall2_id,
                "allowed": [{"IPProtocol": "TCP"}],
                "sourceRanges": ["0.0.0.0/0"],
                "direction": "EGRESS",
            },
            {
                "name": "firewall3",
                "id": firewall3_id,
                "allowed": [{"IPProtocol": "TCP"}],
                "sourceRanges": ["10.0.15.0/24"],
                "direction": "INGRESS",
            },
        ]
    }
    client.firewalls().list_next.return_value = None


def mock_api_urlMaps_calls(client: MagicMock):
    url_map1_id = str(uuid4())
    url_map2_id = str(uuid4())

    client.urlMaps().list().execute.return_value = {
        "items": [
            {
                "name": "url_map1",
                "id": url_map1_id,
                "defaultService": "service1",
            },
            {
                "name": "url_map2",
                "id": url_map2_id,
                "defaultService": "service2",
            },
        ]
    }
    client.urlMaps().list_next.return_value = None

    client.backendServices().get().execute.side_effect = [
        {
            "logConfig": {"enable": True},
        },
        {
            "logConfig": {"enable": False},
        },
    ]


def mock_api_managedZones_calls(client: MagicMock):
    managed_zone1_id = str(uuid4())
    managed_zone2_id = str(uuid4())

    client.managedZones().list().execute.return_value = {
        "managedZones": [
            {
                "name": "managed_zone1",
                "id": managed_zone1_id,
                "dnssecConfig": {"state": "on", "defaultKeySpecs": []},
            },
            {
                "name": "managed_zone2",
                "id": managed_zone2_id,
                "dnssecConfig": {"state": "off", "defaultKeySpecs": []},
            },
        ]
    }
    client.managedZones().list_next.return_value = None


def mock_api_policies_calls(client: MagicMock):
    policy1_id = str(uuid4())
    policy2_id = str(uuid4())

    client.policies().list().execute.return_value = {
        "policies": [
            {
                "name": "policy1",
                "id": policy1_id,
                "enableLogging": True,
                "networks": [
                    {
                        "networkUrl": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/network1"
                    }
                ],
            },
            {
                "name": "policy2",
                "id": policy2_id,
                "enableLogging": False,
                "networks": [],
            },
        ]
    }
    client.policies().list_next.return_value = None


def mock_api_sink_calls(client: MagicMock):
    client.sinks().list().execute.return_value = {
        "sinks": [
            {
                "name": "sink1",
                "destination": "storage.googleapis.com/example-bucket",
                "filter": "all",
                "project_id": GCP_PROJECT_ID,
            },
            {
                "name": "sink2",
                "destination": f"bigquery.googleapis.com/projects/{GCP_PROJECT_ID}/datasets/example_dataset",
                "filter": "all",
                "project_id": GCP_PROJECT_ID,
            },
        ]
    }
    client.sinks().list_next.return_value = None


def mock_api_services_calls(client: MagicMock):
    client.services().list().execute.return_value = {
        "services": [
            {
                "name": f"projects/{GCP_PROJECT_ID}/services/artifacts.googleapis.com",
                "config": {"title": "artifacts.googleapis.com"},
                "state": "ENABLED",
            },
            {
                "name": f"projects/{GCP_PROJECT_ID}/services/bigquery.googleapis.com",
                "config": {"title": "bigquery.googleapis.com"},
                "state": "ENABLED",
            },
        ]
    }
    client.services().list_next.return_value = None
