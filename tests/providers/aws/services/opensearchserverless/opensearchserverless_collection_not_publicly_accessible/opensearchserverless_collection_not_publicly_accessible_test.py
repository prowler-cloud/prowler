import json
from unittest import mock

import botocore
from boto3 import client
from botocore.exceptions import ClientError
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CHECK_MODULE = "prowler.providers.aws.services.opensearchserverless.opensearchserverless_collection_not_publicly_accessible.opensearchserverless_collection_not_publicly_accessible"

orig_make_api_call = botocore.client.BaseClient._make_api_call


def create_collection(aoss_client, name):
    """Create a collection with moto, which requires a matching encryption policy."""
    aoss_client.create_security_policy(
        name=f"enc-{name}",
        type="encryption",
        policy=json.dumps(
            {
                "Rules": [
                    {"ResourceType": "collection", "Resource": [f"collection/{name}"]}
                ],
                "AWSOwnedKey": False,
                "KmsARN": f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/test",
            }
        ),
    )
    return aoss_client.create_collection(name=name, type="SEARCH")[
        "createCollectionDetail"
    ]


def create_network_policy(
    aoss_client, name, patterns, allow_from_public, resource_type="collection"
):
    """Create a network policy with a single rule."""
    aoss_client.create_security_policy(
        name=name,
        type="network",
        policy=json.dumps(
            [
                {
                    "Rules": [{"ResourceType": resource_type, "Resource": patterns}],
                    "AllowFromPublic": allow_from_public,
                }
            ]
        ),
    )


def deny_get_security_policy(policy_name):
    """Build a botocore mock that denies reading one network policy."""

    def mock_make_api_call(self, operation_name, kwarg):
        if operation_name == "GetSecurityPolicy" and kwarg["name"] == policy_name:
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
                operation_name,
            )
        return orig_make_api_call(self, operation_name, kwarg)

    return mock_make_api_call


def execute_check():
    """Build the service with the current moto state and run the check."""
    from prowler.providers.aws.services.opensearchserverless.opensearchserverless_service import (
        OpenSearchServerless,
    )

    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(
            f"{CHECK_MODULE}.opensearchserverless_client",
            new=OpenSearchServerless(aws_provider),
        ),
    ):
        from prowler.providers.aws.services.opensearchserverless.opensearchserverless_collection_not_publicly_accessible.opensearchserverless_collection_not_publicly_accessible import (
            opensearchserverless_collection_not_publicly_accessible,
        )

        check = opensearchserverless_collection_not_publicly_accessible()
        return check.execute()


class Test_opensearchserverless_collection_not_publicly_accessible:
    @mock_aws
    def test_no_collections(self):
        assert execute_check() == []

    @mock_aws
    def test_collection_public_through_collection_endpoint(self):
        aoss_client = client("opensearchserverless", region_name=AWS_REGION_US_EAST_1)
        detail = create_collection(aoss_client, "logs-prod")
        create_network_policy(aoss_client, "net-public", ["collection/logs-*"], True)

        result = execute_check()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended == (
            "OpenSearch Serverless collection logs-prod is publicly accessible "
            "through its collection endpoint by network policy net-public."
        )
        assert result[0].resource_id == detail["id"]
        assert result[0].resource_arn == detail["arn"]
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_collection_public_through_dashboard_endpoint(self):
        aoss_client = client("opensearchserverless", region_name=AWS_REGION_US_EAST_1)
        create_collection(aoss_client, "logs-prod")
        create_network_policy(aoss_client, "net-private", ["collection/logs-*"], False)
        create_network_policy(
            aoss_client,
            "net-dashboards",
            ["collection/logs-prod"],
            True,
            resource_type="dashboard",
        )

        result = execute_check()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended == (
            "OpenSearch Serverless collection logs-prod is publicly accessible "
            "through its dashboard endpoint by network policy net-dashboards."
        )

    @mock_aws
    def test_public_rule_overrides_private_rule(self):
        aoss_client = client("opensearchserverless", region_name=AWS_REGION_US_EAST_1)
        create_collection(aoss_client, "logs-prod")
        create_network_policy(aoss_client, "net-private", ["collection/logs-*"], False)
        create_network_policy(aoss_client, "net-public", ["collection/logs-prod"], True)

        result = execute_check()

        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_collection_private(self):
        aoss_client = client("opensearchserverless", region_name=AWS_REGION_US_EAST_1)
        create_collection(aoss_client, "logs-prod")
        create_network_policy(aoss_client, "net-private", ["collection/logs-*"], False)

        result = execute_check()

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].status_extended == (
            "OpenSearch Serverless collection logs-prod is not publicly accessible."
        )

    @mock_aws
    def test_public_rule_with_undetermined_pattern_is_manual(self):
        aoss_client = client("opensearchserverless", region_name=AWS_REGION_US_EAST_1)
        create_collection(aoss_client, "logs-prod")
        create_network_policy(aoss_client, "net-private", ["collection/logs-*"], False)
        create_network_policy(aoss_client, "net-wildcard", ["collection/*-prod"], True)

        result = execute_check()

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "net-wildcard" in result[0].status_extended

    @mock_aws
    def test_unreadable_policy_is_manual(self):
        aoss_client = client("opensearchserverless", region_name=AWS_REGION_US_EAST_1)
        create_collection(aoss_client, "logs-prod")
        create_network_policy(aoss_client, "net-private", ["collection/logs-*"], False)
        create_network_policy(aoss_client, "net-denied", ["collection/other"], False)

        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=deny_get_security_policy("net-denied"),
        ):
            result = execute_check()

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "not all network policies" in result[0].status_extended

    @mock_aws
    def test_readable_public_rule_fails_even_if_another_policy_is_unreadable(self):
        aoss_client = client("opensearchserverless", region_name=AWS_REGION_US_EAST_1)
        create_collection(aoss_client, "logs-prod")
        create_network_policy(aoss_client, "net-public", ["collection/logs-*"], True)
        create_network_policy(aoss_client, "net-denied", ["collection/other"], False)

        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=deny_get_security_policy("net-denied"),
        ):
            result = execute_check()

        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_collection_not_covered_by_any_rule_is_manual(self):
        aoss_client = client("opensearchserverless", region_name=AWS_REGION_US_EAST_1)
        create_collection(aoss_client, "logs-prod")
        create_network_policy(aoss_client, "net-web", ["collection/web-*"], False)

        result = execute_check()

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "not covered by any network policy rule" in result[0].status_extended
