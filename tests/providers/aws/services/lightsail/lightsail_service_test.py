from unittest.mock import patch

import botocore

from prowler.providers.aws.services.lightsail.lightsail_service import Lightsail
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    AWS_REGION_US_EAST_1_AZA,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "GetInstances":
        return {
            "instances": [
                {
                    "addOns": [
                        {
                            "name": "AutoSnapshot",
                            "snapshotTimeOfDay": "06:00",
                            "status": "Enabled",
                        }
                    ],
                    "arn": f"arn:aws:lightsail:{AWS_REGION_US_EAST_1}:106908755756:Instance/test-id",
                    "blueprintId": "wordpress",
                    "blueprintName": "WordPress",
                    "bundleId": "nano_3_0",
                    "createdAt": "2024-04-30T10:56:00.273000-04:00",
                    "hardware": {
                        "cpuCount": 2,
                        "disks": [
                            {
                                "attachedTo": "WordPress-1",
                                "attachmentState": "attached",
                                "createdAt": "2024-04-30T10:56:00.273000-04:00",
                                "iops": 100,
                                "isSystemDisk": True,
                                "path": "/dev/xvda",
                                "sizeInGb": 20,
                            },
                            {
                                "arn": f"arn:aws:lightsail:{AWS_REGION_US_EAST_1}:106908755756:Disk/028e6d56-8ab8-41cf-b681-df41911eaeac",
                                "attachedTo": "WordPress-1",
                                "attachmentState": "attached",
                                "createdAt": "2024-04-30T11:01:08.869000-04:00",
                                "iops": 100,
                                "isAttached": True,
                                "isSystemDisk": False,
                                "location": {
                                    "availabilityZone": AWS_REGION_US_EAST_1_AZA,
                                    "regionName": AWS_REGION_US_EAST_1,
                                },
                                "name": "Disk-1",
                                "path": "/dev/xvdf",
                                "resourceType": "Disk",
                                "sizeInGb": 8,
                                "state": "in-use",
                                "supportCode": "578520385941/vol-050b0c93d47ef1975",
                                "tags": [],
                            },
                        ],
                        "ramSizeInGb": 0.5,
                    },
                    "ipAddressType": "ipv4",
                    "ipv6Addresses": [],
                    "isStaticIp": False,
                    "location": {
                        "availabilityZone": AWS_REGION_US_EAST_1_AZA,
                        "regionName": AWS_REGION_US_EAST_1,
                    },
                    "metadataOptions": {
                        "httpEndpoint": "enabled",
                        "httpProtocolIpv6": "disabled",
                        "httpPutResponseHopLimit": 1,
                        "httpTokens": "optional",
                        "state": "applied",
                    },
                    "name": "WordPress-1",
                    "networking": {
                        "monthlyTransfer": {"gbPerMonthAllocated": 1024},
                        "ports": [
                            {
                                "accessDirection": "inbound",
                                "accessFrom": "Anywhere (::/0)",
                                "accessType": "public",
                                "cidrListAliases": [],
                                "cidrs": [],
                                "commonName": "",
                                "fromPort": 80,
                                "ipv6Cidrs": ["::/0"],
                                "protocol": "tcp",
                                "toPort": 80,
                            },
                            {
                                "accessDirection": "inbound",
                                "accessFrom": "Anywhere (::/0)",
                                "accessType": "public",
                                "cidrListAliases": [],
                                "cidrs": [],
                                "commonName": "",
                                "fromPort": 22,
                                "ipv6Cidrs": ["::/0"],
                                "protocol": "tcp",
                                "toPort": 22,
                            },
                            {
                                "accessDirection": "inbound",
                                "accessFrom": "Anywhere (::/0)",
                                "accessType": "public",
                                "cidrListAliases": [],
                                "cidrs": [],
                                "commonName": "",
                                "fromPort": 443,
                                "ipv6Cidrs": ["::/0"],
                                "protocol": "tcp",
                                "toPort": 443,
                            },
                        ],
                    },
                    "privateIpAddress": "172.26.7.65",
                    "publicIpAddress": "1.2.3.4",
                    "resourceType": "Instance",
                    "sshKeyName": "LightsailDefaultKeyPair",
                    "state": {"code": 16, "name": "running"},
                    "supportCode": "578520385941/i-04eb483325cca5364",
                    "tags": [],
                    "username": "bitnami",
                }
            ]
        }
    elif operation_name == "GetRelationalDatabases":
        return {
            "relationalDatabases": [
                {
                    "arn": f"arn:aws:lightsail:{AWS_REGION_US_EAST_1}:106908755756:Database/test-id",
                    "backupRetention": 7,
                    "backupRetentionCount": 7,
                    "createdAt": "2024-04-30T10:56:00.273000-04:00",
                    "engine": "mysql",
                    "engineVersion": "8.0.23",
                    "latestRestorableTime": "2024-04-30T10:56:00.273000-04:00",
                    "location": {
                        "availabilityZone": AWS_REGION_US_EAST_1_AZA,
                        "regionName": AWS_REGION_US_EAST_1,
                    },
                    "masterUsername": "admin",
                    "name": "test-db",
                    "resourceType": "Database",
                    "state": "running",
                    "supportCode": "578520385941/db-0a0f5d4e2b3a4e4f",
                    "tags": [],
                    "publiclyAccessible": False,
                }
            ]
        }

    return make_api_call(self, operation_name, kwarg)


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class TestLightsailService:
    def test_service(self):
        lightsail = Lightsail(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        # General assertions
        assert lightsail.service == "lightsail"
        assert lightsail.client.__class__.__name__ == "Lightsail"
        assert lightsail.session.__class__.__name__ == "Session"
        assert lightsail.audited_account == AWS_ACCOUNT_NUMBER
        # Instances assertions
        assert lightsail.instances[0].name == "WordPress-1"
        assert (
            lightsail.instances[0].arn
            == "arn:aws:lightsail:us-east-1:106908755756:Instance/test-id"
        )
        assert lightsail.instances[0].tags == []
        assert lightsail.instances[0].location == {
            "availabilityZone": "us-east-1a",
            "regionName": "us-east-1",
        }
        assert not lightsail.instances[0].static_ip
        assert lightsail.instances[0].public_ip == "1.2.3.4"
        assert lightsail.instances[0].private_ip == "172.26.7.65"
        assert lightsail.instances[0].ipv6_addresses == []
        assert lightsail.instances[0].ip_address_type == "ipv4"
        assert len(lightsail.instances[0].ports) == 3
        assert lightsail.instances[0].ports[0].range == "80"
        assert lightsail.instances[0].ports[0].protocol == "tcp"
        assert lightsail.instances[0].ports[0].access_from == "Anywhere (::/0)"
        assert lightsail.instances[0].ports[0].access_type == "public"
        assert lightsail.instances[0].ports[1].range == "22"
        assert lightsail.instances[0].ports[1].protocol == "tcp"
        assert lightsail.instances[0].ports[1].access_from == "Anywhere (::/0)"
        assert lightsail.instances[0].ports[1].access_type == "public"
        assert lightsail.instances[0].ports[2].range == "443"
        assert lightsail.instances[0].ports[2].protocol == "tcp"
        assert lightsail.instances[0].ports[2].access_from == "Anywhere (::/0)"
        assert lightsail.instances[0].ports[2].access_type == "public"
        assert lightsail.instances[0].auto_snapshot
        # Databases assertions
        assert lightsail.databases[0].name == "test-db"
        assert (
            lightsail.databases[0].arn
            == "arn:aws:lightsail:us-east-1:106908755756:Database/test-id"
        )
        assert lightsail.databases[0].tags == []
        assert lightsail.databases[0].location == {
            "availabilityZone": "us-east-1a",
            "regionName": "us-east-1",
        }
        assert lightsail.databases[0].engine == "mysql"
        assert lightsail.databases[0].engine_version == "8.0.23"
        assert lightsail.databases[0].status == "running"
        assert lightsail.databases[0].username == "admin"
        assert not lightsail.databases[0].public_access
