import json
from unittest.mock import patch

import botocore
from boto3 import client
from botocore.exceptions import ClientError
from moto import mock_aws

from prowler.providers.aws.services.opensearchserverless.lib.network_policy import (
    NetworkPolicyRule,
)
from prowler.providers.aws.services.opensearchserverless.opensearchserverless_service import (
    OpenSearchServerless,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

orig_make_api_call = botocore.client.BaseClient._make_api_call


def create_collection(aoss_client, name, tags=None):
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
    kwargs = {"name": name, "type": "SEARCH"}
    if tags:
        kwargs["tags"] = tags
    return aoss_client.create_collection(**kwargs)["createCollectionDetail"]


def create_network_policy(aoss_client, name, patterns, allow_from_public):
    """Create a network policy with a single collection rule."""
    aoss_client.create_security_policy(
        name=name,
        type="network",
        policy=json.dumps(
            [
                {
                    "Rules": [{"ResourceType": "collection", "Resource": patterns}],
                    "AllowFromPublic": allow_from_public,
                }
            ]
        ),
    )


def network_policy_document(patterns, allow_from_public):
    """Build the policy document AWS returns for a single collection rule."""
    return [
        {
            "Rules": [{"ResourceType": "collection", "Resource": patterns}],
            "AllowFromPublic": allow_from_public,
        }
    ]


def access_denied(operation_name):
    """Build an AccessDenied error for the given operation."""
    return ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "Access denied"}},
        operation_name,
    )


def get_collection(service, name):
    """Return the collection with the given name from the service."""
    return next(c for c in service.collections.values() if c.name == name)


class Test_OpenSearchServerless_Service:
    @mock_aws
    def test_service_client(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        opensearchserverless = OpenSearchServerless(aws_provider)

        assert opensearchserverless.service == "opensearchserverless"
        for regional_client in opensearchserverless.regional_clients.values():
            assert regional_client.__class__.__name__ == "OpenSearchServiceServerless"

    @mock_aws
    def test_no_collections(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        opensearchserverless = OpenSearchServerless(aws_provider)

        assert opensearchserverless.collections == {}
        assert opensearchserverless.network_rules == {}

    @mock_aws
    def test_collection_attributes_and_tags(self):
        aoss_client = client("opensearchserverless", region_name=AWS_REGION_US_EAST_1)
        detail = create_collection(
            aoss_client, "logs-prod", tags=[{"key": "env", "value": "prod"}]
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        opensearchserverless = OpenSearchServerless(aws_provider)

        assert len(opensearchserverless.collections) == 1
        collection = opensearchserverless.collections[detail["arn"]]
        assert collection.id == detail["id"]
        assert collection.name == "logs-prod"
        assert collection.arn == detail["arn"]
        assert collection.region == AWS_REGION_US_EAST_1
        assert collection.status == "ACTIVE"
        assert collection.tags == [{"key": "env", "value": "prod"}]

    @mock_aws
    def test_public_rule_that_covers_the_collection(self):
        aoss_client = client("opensearchserverless", region_name=AWS_REGION_US_EAST_1)
        create_collection(aoss_client, "logs-prod")
        create_network_policy(aoss_client, "net-logs", ["collection/logs-*"], True)

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        opensearchserverless = OpenSearchServerless(aws_provider)

        collection = get_collection(opensearchserverless, "logs-prod")
        assert collection.network_rules == [
            NetworkPolicyRule(
                policy_name="net-logs",
                resource_type="collection",
                patterns=["collection/logs-*"],
                allow_from_public=True,
            )
        ]
        assert collection.doubtful_network_rules == []
        assert collection.network_policies_complete is True

    @mock_aws
    def test_rule_that_does_not_cover_the_collection_is_discarded(self):
        aoss_client = client("opensearchserverless", region_name=AWS_REGION_US_EAST_1)
        create_collection(aoss_client, "logs-prod")
        create_network_policy(aoss_client, "net-web", ["collection/web-*"], True)

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        opensearchserverless = OpenSearchServerless(aws_provider)

        collection = get_collection(opensearchserverless, "logs-prod")
        assert collection.network_rules == []
        assert collection.doubtful_network_rules == []
        assert collection.network_policies_complete is True

    @mock_aws
    def test_rule_with_undetermined_pattern_is_doubtful(self):
        aoss_client = client("opensearchserverless", region_name=AWS_REGION_US_EAST_1)
        create_collection(aoss_client, "logs-prod")
        create_network_policy(aoss_client, "net-prod", ["collection/*-prod"], True)

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        opensearchserverless = OpenSearchServerless(aws_provider)

        collection = get_collection(opensearchserverless, "logs-prod")
        assert collection.network_rules == []
        assert [rule.policy_name for rule in collection.doubtful_network_rules] == [
            "net-prod"
        ]
        assert collection.network_policies_complete is True

    @mock_aws
    def test_rules_are_mapped_to_each_collection(self):
        aoss_client = client("opensearchserverless", region_name=AWS_REGION_US_EAST_1)
        create_collection(aoss_client, "logs-prod")
        create_collection(aoss_client, "web-prod")
        create_network_policy(aoss_client, "net-logs", ["collection/logs-*"], False)

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        opensearchserverless = OpenSearchServerless(aws_provider)

        logs = get_collection(opensearchserverless, "logs-prod")
        web = get_collection(opensearchserverless, "web-prod")
        assert [rule.policy_name for rule in logs.network_rules] == ["net-logs"]
        assert web.network_rules == []
        assert logs.doubtful_network_rules == []
        assert web.doubtful_network_rules == []
        assert logs.network_policies_complete is True
        assert web.network_policies_complete is True

    @mock_aws
    def test_region_without_network_policies_is_complete(self):
        aoss_client = client("opensearchserverless", region_name=AWS_REGION_US_EAST_1)
        create_collection(aoss_client, "logs-prod")

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        opensearchserverless = OpenSearchServerless(aws_provider)

        collection = get_collection(opensearchserverless, "logs-prod")
        assert collection.network_rules == []
        assert collection.doubtful_network_rules == []
        assert collection.network_policies_complete is True

    @mock_aws
    def test_unreadable_policy_keeps_readable_rules_and_marks_region_incomplete(
        self,
    ):
        aoss_client = client("opensearchserverless", region_name=AWS_REGION_US_EAST_1)
        create_collection(aoss_client, "logs-prod")
        # The failing policy is listed first, so the test also proves that the
        # policies after a failure are still read
        create_network_policy(aoss_client, "net-denied", ["collection/logs-*"], True)
        create_network_policy(aoss_client, "net-readable", ["collection/logs-*"], True)

        def mock_make_api_call(self, operation_name, kwarg):
            if operation_name == "GetSecurityPolicy" and kwarg["name"] == "net-denied":
                raise access_denied(operation_name)
            return orig_make_api_call(self, operation_name, kwarg)

        with patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call):
            aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
            opensearchserverless = OpenSearchServerless(aws_provider)

        collection = get_collection(opensearchserverless, "logs-prod")
        assert [rule.policy_name for rule in collection.network_rules] == [
            "net-readable"
        ]
        assert collection.doubtful_network_rules == []
        assert collection.network_policies_complete is False

    @mock_aws
    def test_policy_with_unexpected_format_marks_region_incomplete(self):
        aoss_client = client("opensearchserverless", region_name=AWS_REGION_US_EAST_1)
        create_collection(aoss_client, "logs-prod")
        create_network_policy(aoss_client, "net-odd", ["collection/logs-*"], True)

        def mock_make_api_call(self, operation_name, kwarg):
            if operation_name == "GetSecurityPolicy":
                return {
                    "securityPolicyDetail": {
                        "name": kwarg["name"],
                        "type": "network",
                        "policy": {"Rules": [], "AllowFromPublic": True},
                    }
                }
            return orig_make_api_call(self, operation_name, kwarg)

        with patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call):
            aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
            opensearchserverless = OpenSearchServerless(aws_provider)

        collection = get_collection(opensearchserverless, "logs-prod")
        assert collection.network_rules == []
        assert collection.doubtful_network_rules == []
        assert collection.network_policies_complete is False

    @mock_aws
    def test_list_security_policies_error_marks_region_incomplete(self):
        aoss_client = client("opensearchserverless", region_name=AWS_REGION_US_EAST_1)
        create_collection(aoss_client, "logs-prod")
        create_network_policy(aoss_client, "net-logs", ["collection/logs-*"], False)

        def mock_make_api_call(self, operation_name, kwarg):
            if operation_name == "ListSecurityPolicies":
                raise access_denied(operation_name)
            return orig_make_api_call(self, operation_name, kwarg)

        with patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call):
            aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
            opensearchserverless = OpenSearchServerless(aws_provider)

        collection = get_collection(opensearchserverless, "logs-prod")
        assert collection.network_rules == []
        assert collection.doubtful_network_rules == []
        assert collection.network_policies_complete is False

    @mock_aws
    def test_network_policies_are_paginated(self):
        aoss_client = client("opensearchserverless", region_name=AWS_REGION_US_EAST_1)
        create_collection(aoss_client, "logs-prod")

        def mock_make_api_call(self, operation_name, kwarg):
            if operation_name == "ListSecurityPolicies":
                if kwarg.get("nextToken") == "page-2":
                    return {"securityPolicySummaries": [{"name": "net-page-2"}]}
                return {
                    "securityPolicySummaries": [{"name": "net-page-1"}],
                    "nextToken": "page-2",
                }
            if operation_name == "GetSecurityPolicy":
                return {
                    "securityPolicyDetail": {
                        "name": kwarg["name"],
                        "type": "network",
                        "policy": network_policy_document(["collection/logs-*"], False),
                    }
                }
            return orig_make_api_call(self, operation_name, kwarg)

        with patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call):
            aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
            opensearchserverless = OpenSearchServerless(aws_provider)

        collection = get_collection(opensearchserverless, "logs-prod")
        assert sorted(rule.policy_name for rule in collection.network_rules) == [
            "net-page-1",
            "net-page-2",
        ]
        assert collection.network_policies_complete is True

    @mock_aws
    def test_collections_are_paginated(self):
        def mock_make_api_call(self, operation_name, kwarg):
            if operation_name == "ListCollections":
                page = 2 if kwarg.get("nextToken") == "page-2" else 1
                response = {
                    "collectionSummaries": [
                        {
                            "id": f"id{page}",
                            "name": f"collection-{page}",
                            "arn": f"arn:aws:aoss:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:collection/id{page}",
                            "status": "ACTIVE",
                        }
                    ]
                }
                if page == 1:
                    response["nextToken"] = "page-2"
                return response
            return orig_make_api_call(self, operation_name, kwarg)

        with patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call):
            aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
            opensearchserverless = OpenSearchServerless(aws_provider)

        assert sorted(c.name for c in opensearchserverless.collections.values()) == [
            "collection-1",
            "collection-2",
        ]

    @mock_aws
    def test_list_collections_error_returns_no_collections(self):
        aoss_client = client("opensearchserverless", region_name=AWS_REGION_US_EAST_1)
        create_collection(aoss_client, "logs-prod")

        def mock_make_api_call(self, operation_name, kwarg):
            if operation_name == "ListCollections":
                raise access_denied(operation_name)
            return orig_make_api_call(self, operation_name, kwarg)

        with patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call):
            aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
            opensearchserverless = OpenSearchServerless(aws_provider)

        assert opensearchserverless.collections == {}
