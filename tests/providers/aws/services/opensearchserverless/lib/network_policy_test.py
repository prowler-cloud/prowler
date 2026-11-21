from prowler.providers.aws.services.opensearchserverless.lib.network_policy import (
    NetworkPolicyRule,
    parse_network_policy,
    resource_pattern_matches,
)


class Test_resource_pattern_matches:
    def test_exact_name_matches(self):
        assert resource_pattern_matches("collection/logs-prod", "logs-prod") is True

    def test_prefix_wildcard_with_hyphen_matches(self):
        assert resource_pattern_matches("collection/logs-*", "logs-prod") is True

    def test_prefix_wildcard_without_hyphen_matches(self):
        assert resource_pattern_matches("collection/logs*", "logs-prod") is True

    def test_single_wildcard_matches_everything(self):
        assert resource_pattern_matches("collection/*", "logs-prod") is True

    def test_different_exact_name_does_not_match(self):
        assert (
            resource_pattern_matches("collection/logs-prod-test", "logs-prod") is False
        )

    def test_uppercase_pattern_is_undetermined(self):
        assert resource_pattern_matches("collection/LOGS-PROD", "logs-prod") is None

    def test_leading_wildcard_is_undetermined(self):
        assert resource_pattern_matches("collection/*prod", "logs-prod") is None


class Test_parse_network_policy:
    # Caso 1
    def test_single_private_collection_rule(self):
        policy_document = [
            {
                "Rules": [
                    {
                        "ResourceType": "collection",
                        "Resource": ["collection/logs-*"],
                    }
                ],
                "AllowFromPublic": False,
            }
        ]

        assert parse_network_policy("my-policy", policy_document) == [
            NetworkPolicyRule(
                policy_name="my-policy",
                resource_type="collection",
                patterns=["collection/logs-*"],
                allow_from_public=False,
            )
        ]

    # Caso 2
    def test_collection_and_dashboard_rules_in_public_block(self):
        policy_document = [
            {
                "Rules": [
                    {
                        "ResourceType": "collection",
                        "Resource": ["collection/logs-*"],
                    },
                    {
                        "ResourceType": "dashboard",
                        "Resource": ["collection/web-*"],
                    },
                ],
                "AllowFromPublic": True,
            }
        ]

        assert parse_network_policy("my-policy", policy_document) == [
            NetworkPolicyRule(
                policy_name="my-policy",
                resource_type="collection",
                patterns=["collection/logs-*"],
                allow_from_public=True,
            ),
            NetworkPolicyRule(
                policy_name="my-policy",
                resource_type="dashboard",
                patterns=["collection/web-*"],
                allow_from_public=True,
            ),
        ]

    # Caso 3
    def test_each_rule_inherits_its_own_block_allow_from_public(self):
        policy_document = [
            {
                "Rules": [
                    {
                        "ResourceType": "collection",
                        "Resource": ["collection/logs-*"],
                    }
                ],
                "AllowFromPublic": False,
            },
            {
                "Rules": [
                    {
                        "ResourceType": "collection",
                        "Resource": ["collection/logs-collection1"],
                    }
                ],
                "AllowFromPublic": True,
            },
        ]

        assert parse_network_policy("my-policy", policy_document) == [
            NetworkPolicyRule(
                policy_name="my-policy",
                resource_type="collection",
                patterns=["collection/logs-*"],
                allow_from_public=False,
            ),
            NetworkPolicyRule(
                policy_name="my-policy",
                resource_type="collection",
                patterns=["collection/logs-collection1"],
                allow_from_public=True,
            ),
        ]

    # Caso 4
    def test_rule_with_multiple_patterns(self):
        policy_document = [
            {
                "Rules": [
                    {
                        "ResourceType": "collection",
                        "Resource": [
                            "collection/logs-*",
                            "collection/logs-collection1",
                        ],
                    }
                ],
                "AllowFromPublic": False,
            }
        ]

        assert parse_network_policy("my-policy", policy_document) == [
            NetworkPolicyRule(
                policy_name="my-policy",
                resource_type="collection",
                patterns=["collection/logs-*", "collection/logs-collection1"],
                allow_from_public=False,
            )
        ]

    # Caso 5
    def test_public_block_with_vpc_endpoints_is_public(self):
        policy_document = [
            {
                "Rules": [
                    {
                        "ResourceType": "collection",
                        "Resource": ["collection/logs-*"],
                    }
                ],
                "AllowFromPublic": True,
                "SourceVPCEs": ["vpce-123"],
            }
        ]

        assert parse_network_policy("my-policy", policy_document) == [
            NetworkPolicyRule(
                policy_name="my-policy",
                resource_type="collection",
                patterns=["collection/logs-*"],
                allow_from_public=True,
            )
        ]

    # Caso 6
    def test_empty_policy_returns_empty_list(self):
        assert parse_network_policy("my-policy", []) == []

    # Caso 7
    def test_dict_instead_of_list_is_unreadable(self):
        policy_document = {
            "Rules": [
                {
                    "ResourceType": "collection",
                    "Resource": ["collection/logs-*"],
                }
            ],
            "AllowFromPublic": False,
        }

        assert parse_network_policy("my-policy", policy_document) is None

    # Caso 8
    def test_missing_allow_from_public_is_unreadable(self):
        policy_document = [
            {
                "Rules": [
                    {
                        "ResourceType": "collection",
                        "Resource": ["collection/logs-*"],
                    }
                ],
            }
        ]

        assert parse_network_policy("my-policy", policy_document) is None

    # Caso 9
    def test_string_allow_from_public_is_unreadable(self):
        policy_document = [
            {
                "Rules": [
                    {
                        "ResourceType": "collection",
                        "Resource": ["collection/logs-*"],
                    }
                ],
                "AllowFromPublic": "true",
            }
        ]

        assert parse_network_policy("my-policy", policy_document) is None

    # Caso 10
    def test_unknown_resource_type_is_unreadable(self):
        policy_document = [
            {
                "Rules": [
                    {
                        "ResourceType": "index",
                        "Resource": ["collection/logs-*"],
                    }
                ],
                "AllowFromPublic": True,
            }
        ]

        assert parse_network_policy("my-policy", policy_document) is None

    # Caso 11
    def test_public_block_with_empty_rules_returns_empty_list(self):
        policy_document = [
            {
                "Rules": [],
                "AllowFromPublic": True,
            }
        ]

        assert parse_network_policy("my-policy", policy_document) == []

    # Caso 12
    def test_resource_as_string_is_unreadable(self):
        policy_document = [
            {
                "Rules": [
                    {
                        "ResourceType": "collection",
                        "Resource": "collection/logs-*",
                    }
                ],
                "AllowFromPublic": True,
            }
        ]

        assert parse_network_policy("my-policy", policy_document) is None

    # Caso 13
    def test_missing_resource_type_is_unreadable(self):
        policy_document = [
            {
                "Rules": [
                    {
                        "Resource": ["collection/logs-*"],
                    }
                ],
                "AllowFromPublic": True,
            }
        ]

        assert parse_network_policy("my-policy", policy_document) is None
