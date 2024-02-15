from unittest import mock
from uuid import uuid4

from azure.mgmt.network.models._models import SecurityRule

from prowler.providers.azure.services.network.network_service import SecurityGroup

AZURE_SUBSCRIPTION = str(uuid4())


class Test_network_ssh_internet_access_restricted:
    def test_no_security_groups(self):
        network_client = mock.MagicMock
        network_client.security_groups = {}

        with mock.patch(
            "prowler.providers.azure.services.network.network_ssh_internet_access_restricted.network_ssh_internet_access_restricted.network_client",
            new=network_client,
        ):
            from prowler.providers.azure.services.network.network_ssh_internet_access_restricted.network_ssh_internet_access_restricted import (
                network_ssh_internet_access_restricted,
            )

            check = network_ssh_internet_access_restricted()
            result = check.execute()
            assert len(result) == 0

    def test_network_security_groups_no_security_rules(self):
        network_client = mock.MagicMock
        security_group_name = "Security Group Name"
        security_group_id = str(uuid4())

        network_client.security_groups = {
            AZURE_SUBSCRIPTION: [
                SecurityGroup(
                    id=security_group_id,
                    name=security_group_name,
                    location="location",
                    security_rules=[],
                    network_watchers=None,
                    subscription_locations=None,
                    flow_logs=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.network.network_ssh_internet_access_restricted.network_ssh_internet_access_restricted.network_client",
            new=network_client,
        ):
            from prowler.providers.azure.services.network.network_ssh_internet_access_restricted.network_ssh_internet_access_restricted import (
                network_ssh_internet_access_restricted,
            )

            check = network_ssh_internet_access_restricted()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Security Group {security_group_name} from subscription {AZURE_SUBSCRIPTION} has SSH internet access restricted."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == security_group_name
            assert result[0].resource_id == security_group_id

    def test_network_security_groups_invalid_security_rules(self):
        network_client = mock.MagicMock
        security_group_name = "Security Group Name"
        security_group_id = str(uuid4())

        network_client.security_groups = {
            AZURE_SUBSCRIPTION: [
                SecurityGroup(
                    id=security_group_id,
                    name=security_group_name,
                    location="location",
                    security_rules=[
                        SecurityRule(
                            destination_port_range="22",
                            protocol="TCP",
                            source_address_prefix="Internet",
                            access="Allow",
                            direction="Inbound",
                        )
                    ],
                    network_watchers=None,
                    subscription_locations=None,
                    flow_logs=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.network.network_ssh_internet_access_restricted.network_ssh_internet_access_restricted.network_client",
            new=network_client,
        ):
            from prowler.providers.azure.services.network.network_ssh_internet_access_restricted.network_ssh_internet_access_restricted import (
                network_ssh_internet_access_restricted,
            )

            check = network_ssh_internet_access_restricted()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Security Group {security_group_name} from subscription {AZURE_SUBSCRIPTION} has SSH internet access allowed."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == security_group_name
            assert result[0].resource_id == security_group_id

    def test_network_security_groups_valid_security_rules(self):
        network_client = mock.MagicMock
        security_group_name = "Security Group Name"
        security_group_id = str(uuid4())

        network_client.security_groups = {
            AZURE_SUBSCRIPTION: [
                SecurityGroup(
                    id=security_group_id,
                    name=security_group_name,
                    location="location",
                    security_rules=[
                        SecurityRule(
                            destination_port_range="23",
                            protocol="TCP",
                            source_address_prefix="Internet",
                            access="Allow",
                            direction="Inbound",
                        )
                    ],
                    network_watchers=None,
                    subscription_locations=None,
                    flow_logs=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.network.network_ssh_internet_access_restricted.network_ssh_internet_access_restricted.network_client",
            new=network_client,
        ):
            from prowler.providers.azure.services.network.network_ssh_internet_access_restricted.network_ssh_internet_access_restricted import (
                network_ssh_internet_access_restricted,
            )

            check = network_ssh_internet_access_restricted()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Security Group {security_group_name} from subscription {AZURE_SUBSCRIPTION} has SSH internet access restricted."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == security_group_name
            assert result[0].resource_id == security_group_id
