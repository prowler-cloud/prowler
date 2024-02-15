from unittest import mock
from uuid import uuid4

from azure.mgmt.network.models._models import FlowLog, RetentionPolicyParameters

from prowler.providers.azure.services.network.network_service import SecurityGroup

AZURE_SUBSCRIPTION = str(uuid4())


class Test_network_flow_log_more_than_90_days:
    def test_no_security_groups(self):
        network_client = mock.MagicMock
        network_client.security_groups = {}

        with mock.patch(
            "prowler.providers.azure.services.network.network_flow_log_more_than_90_days.network_flow_log_more_than_90_days.network_client",
            new=network_client,
        ):
            from prowler.providers.azure.services.network.network_flow_log_more_than_90_days.network_flow_log_more_than_90_days import (
                network_flow_log_more_than_90_days,
            )

            check = network_flow_log_more_than_90_days()
            result = check.execute()
            assert len(result) == 0

    def test_network_security_groups_no_flow_logs(self):
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
                    flow_logs=[],
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.network.network_flow_log_more_than_90_days.network_flow_log_more_than_90_days.network_client",
            new=network_client,
        ):
            from prowler.providers.azure.services.network.network_flow_log_more_than_90_days.network_flow_log_more_than_90_days import (
                network_flow_log_more_than_90_days,
            )

            check = network_flow_log_more_than_90_days()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Security Group {security_group_name} from subscription {AZURE_SUBSCRIPTION} has no flow logs"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == security_group_name
            assert result[0].resource_id == security_group_id

    def test_network_security_groups_flow_logs_disabled(self):
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
                    flow_logs=[
                        FlowLog(
                            enabled=False,
                            retention_policy=RetentionPolicyParameters(days=90),
                        )
                    ],
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.network.network_flow_log_more_than_90_days.network_flow_log_more_than_90_days.network_client",
            new=network_client,
        ):
            from prowler.providers.azure.services.network.network_flow_log_more_than_90_days.network_flow_log_more_than_90_days import (
                network_flow_log_more_than_90_days,
            )

            check = network_flow_log_more_than_90_days()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Security Group {security_group_name} from subscription {AZURE_SUBSCRIPTION} has flow logs disabled"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == security_group_name
            assert result[0].resource_id == security_group_id

    def test_network_security_groups_flow_logs_retention_days_80(self):
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
                    flow_logs=[
                        FlowLog(
                            enabled=True,
                            retention_policy=RetentionPolicyParameters(days=80),
                        )
                    ],
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.network.network_flow_log_more_than_90_days.network_flow_log_more_than_90_days.network_client",
            new=network_client,
        ):
            from prowler.providers.azure.services.network.network_flow_log_more_than_90_days.network_flow_log_more_than_90_days import (
                network_flow_log_more_than_90_days,
            )

            check = network_flow_log_more_than_90_days()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Security Group {security_group_name} from subscription {AZURE_SUBSCRIPTION} flow logs retention policy is less than 90 days"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == security_group_name
            assert result[0].resource_id == security_group_id

    def test_network_security_groups_flow_logs_well_configured(self):
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
                    flow_logs=[
                        FlowLog(
                            enabled=True,
                            retention_policy=RetentionPolicyParameters(days=90),
                        )
                    ],
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.network.network_flow_log_more_than_90_days.network_flow_log_more_than_90_days.network_client",
            new=network_client,
        ):
            from prowler.providers.azure.services.network.network_flow_log_more_than_90_days.network_flow_log_more_than_90_days import (
                network_flow_log_more_than_90_days,
            )

            check = network_flow_log_more_than_90_days()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Security Group {security_group_name} from subscription {AZURE_SUBSCRIPTION} has flow logs enabled for more than 90 days"
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == security_group_name
            assert result[0].resource_id == security_group_id
