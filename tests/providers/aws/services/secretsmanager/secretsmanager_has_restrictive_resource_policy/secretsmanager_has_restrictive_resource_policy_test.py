import json
from unittest import mock
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.secretsmanager.secretsmanager_service import (
    SecretsManager,
)
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider


class Test_secretsmanager_has_restrictive_resource_policy:
    def test_no_secrets(self):
        client("secretsmanager", region_name=AWS_REGION_EU_WEST_1)
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
            new=SecretsManager(aws_provider),
        ):
            from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                secretsmanager_has_restrictive_resource_policy,
            )

            check = secretsmanager_has_restrictive_resource_policy()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_secret_with_weak_policy(self):
        secretsmanager_client = client(
            "secretsmanager", region_name=AWS_REGION_EU_WEST_1
        )
        secret = secretsmanager_client.create_secret(Name="test-secret-weak-policy")
        secretsmanager_client.put_resource_policy(
            SecretId=secret["ARN"],
            ResourcePolicy=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "secretsmanager:GetSecretValue",
                            "Resource": "*",
                        }
                    ],
                },
                indent=4,
            ),
        )
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
            new=SecretsManager(aws_provider),
        ):
            from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                secretsmanager_has_restrictive_resource_policy,
            )

            check = secretsmanager_has_restrictive_resource_policy()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    @mock_aws
    def test_secret_with_restrictive_policy_without_org_id(self):
        secretsmanager_client = client(
            "secretsmanager", region_name=AWS_REGION_EU_WEST_1
        )
        secret = secretsmanager_client.create_secret(Name="test-secret-modified")

        valid_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyUnauthorizedPrincipals",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "StringNotEquals": {
                            "aws:PrincipalArn": [
                                "arn:aws:iam::123456789012:role/AccountSecurityAuditRole"
                            ]
                        }
                    },
                },
                {
                    "Sid": "AllowAuditPolicyRead",
                    "Effect": "Deny",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:role/AccountSecurityAuditRole"
                    },
                    "NotAction": [
                        "secretsmanager:DescribeSecret",
                        "secretsmanager:GetResourcePolicy",
                    ],
                    "Resource": "*",
                },
            ],
        }

        test_cases = [
            (
                "Invalid Policy without DenyOutsideOrganization because OrgID is given",
                valid_policy,
                "FAIL",
                ["o-1234567890"],
            ),
            (
                "Valid Policy without DenyOutsideOrganization because no OrgID is given",
                valid_policy,
                "PASS",
                [],
            ),
        ]

        for description, base_policy, expected_status, trusted_org_ids in test_cases:
            policy_copy = json.loads(json.dumps(base_policy))

            secretsmanager_client.put_resource_policy(
                SecretId=secret["ARN"], ResourcePolicy=json.dumps(policy_copy)
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

            with mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ), mock.patch(
                "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                new=SecretsManager(aws_provider),
            ), mock.patch(
                "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client.audit_config",
                {"organizations_trusted_ids": trusted_org_ids},
            ):
                from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                    secretsmanager_has_restrictive_resource_policy,
                )

                check = secretsmanager_has_restrictive_resource_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == expected_status, f"Test case: {description}"

    @mock_aws
    def test_secret_with_modified_restrictive_policies_for_principals(self):
        secretsmanager_client = client(
            "secretsmanager", region_name=AWS_REGION_EU_WEST_1
        )
        secret = secretsmanager_client.create_secret(Name="test-secret-modified")

        valid_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyUnauthorizedPrincipals",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "StringNotEquals": {
                            "aws:PrincipalArn": [
                                "arn:aws:iam::123456789012:role/AccountSecurityAuditRole",
                                "arn:aws:iam::123456789012:role/Role2",
                            ]
                        }
                    },
                },
                {
                    "Sid": "DenyOutsideOrganization",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "secretsmanager:*",
                    "Resource": "*",
                    "Condition": {
                        "StringNotEquals": {"aws:PrincipalOrgID": "o-1234567890"}
                    },
                },
                {
                    "Sid": "AllowAuditPolicyRead",
                    "Effect": "Deny",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:role/AccountSecurityAuditRole"
                    },
                    "NotAction": [
                        "secretsmanager:DescribeSecret",
                        "secretsmanager:GetResourcePolicy",
                    ],
                    "Resource": "*",
                },
                {
                    "Sid": "AllowSecretAccessForRole2",
                    "Effect": "Deny",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:role/Role2"},
                    "NotAction": ["secretsmanager:GetSecretValue"],
                    "Resource": "*",
                },
            ],
        }

        test_cases = [
            # test unmodified policy
            ("Valid Policy", valid_policy, None, None, "PASS"),
            # test modified statement DenyUnauthorizedPrincipals
            (
                "Invalid Effect in DenyUnauthorizedPrincipals",
                valid_policy,
                None,
                (0, {"Effect": "Allow"}),
                "FAIL",
            ),
            (
                "Valid Effect in DenyUnauthorizedPrincipals",
                valid_policy,
                None,
                (0, {"Effect": "Deny"}),
                "PASS",
            ),
            (
                "Invalid Action in DenyUnauthorizedPrincipals",
                valid_policy,
                None,
                (0, {"Action": "InvalidAction"}),
                "FAIL",
            ),
            (
                "Valid Action in DenyUnauthorizedPrincipals",
                valid_policy,
                None,
                (0, {"Action": "*"}),
                "PASS",
            ),
            (
                "Invalid Resource in DenyUnauthorizedPrincipals",
                valid_policy,
                None,
                (
                    0,
                    {
                        "Resource": "arn:aws:secretsmanager:eu-central-1:123456789012:secret:wrong-secret"
                    },
                ),
                "FAIL",
            ),
            (
                "Valid Resource in DenyUnauthorizedPrincipals",
                valid_policy,
                None,
                (0, {"Resource": "*"}),
                "PASS",
            ),
            (
                "Invalid Condition Operator in DenyUnauthorizedPrincipals",
                valid_policy,
                None,
                (
                    0,
                    {
                        "Condition": {
                            "WrongOperator": {
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/AccountSecurityAuditRole"
                            }
                        }
                    },
                ),
                "FAIL",
            ),
            (
                "Valid Condition Operator in DenyUnauthorizedPrincipals",
                valid_policy,
                None,
                (
                    0,
                    {
                        "Condition": {
                            "StringNotEquals": {
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/AccountSecurityAuditRole"
                            }
                        }
                    },
                ),
                "PASS",
            ),
            (
                "Invalid Condition Key in DenyUnauthorizedPrincipals",
                valid_policy,
                None,
                (
                    0,
                    {
                        "Condition": {
                            "StringNotEquals": {
                                "aws:wrongKey": "arn:aws:iam::123456789012:role/AccountSecurityAuditRole"
                            }
                        }
                    },
                ),
                "FAIL",
            ),
            (
                "Valid Condition Key in DenyUnauthorizedPrincipals",
                valid_policy,
                None,
                (
                    0,
                    {
                        "Condition": {
                            "StringNotEquals": {
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/AccountSecurityAuditRole"
                            }
                        }
                    },
                ),
                "PASS",
            ),
            (
                "Invalid Principal with wildcard in Condition in DenyUnauthorizedPrincipals",
                valid_policy,
                None,
                (
                    0,
                    {
                        "Condition": {
                            "StringNotEquals": {
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/*"
                            }
                        }
                    },
                ),
                "FAIL",
            ),
            (
                "Valid Principal w/o  wildcard in Condition in DenyUnauthorizedPrincipals",
                valid_policy,
                None,
                (
                    0,
                    {
                        "Condition": {
                            "StringNotEquals": {
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/AccountSecurityAuditRole"
                            }
                        }
                    },
                ),
                "PASS",
            ),
            (
                "Invalid Service Principal in Condition in DenyUnauthorizedPrincipals",
                valid_policy,
                None,
                (
                    0,
                    {
                        "Condition": {
                            "StringNotEquals": {
                                "aws:PrincipalServiceName": "invalid.service.com"
                            }
                        }
                    },
                ),
                "FAIL",
            ),
            (
                "Valid Service Principal in Condition in DenyUnauthorizedPrincipals",
                valid_policy,
                None,
                (
                    0,
                    {
                        "Condition": {
                            "StringNotEquals": {
                                "aws:PrincipalServiceName": "valid.amazonaws.com"
                            }
                        }
                    },
                ),
                "PASS",
            ),
            # test modified statement DenyOutsideOrganization
            (
                "Invalid Effect in DenyOutsideOrganization",
                valid_policy,
                None,
                (1, {"Effect": "Allow"}),
                "FAIL",
            ),
            (
                "Valid Effect in DenyOutsideOrganization",
                valid_policy,
                None,
                (1, {"Effect": "Deny"}),
                "PASS",
            ),
            (
                "Invalid Action in DenyOutsideOrganization",
                valid_policy,
                None,
                (1, {"Action": "secretsmanager:InvalidAction"}),
                "FAIL",
            ),
            (
                "Valid Action in DenyOutsideOrganization",
                valid_policy,
                None,
                (1, {"Action": "secretsmanager:*"}),
                "PASS",
            ),
            (
                "Invalid Resource in DenyOutsideOrganization",
                valid_policy,
                None,
                (
                    1,
                    {
                        "Resource": "arn:aws:secretsmanager:eu-central-1:123456789012:secret:wrong-secret"
                    },
                ),
                "FAIL",
            ),
            (
                "Invalid Condition Operator in DenyOutsideOrganization",
                valid_policy,
                None,
                (
                    1,
                    {
                        "Condition": {
                            "WrongOperator": {"aws:PrincipalOrgID": "o-1234567890"}
                        }
                    },
                ),
                "FAIL",
            ),
            (
                "Valid Condition Operator in DenyOutsideOrganization",
                valid_policy,
                None,
                (
                    1,
                    {
                        "Condition": {
                            "StringNotEquals": {"aws:PrincipalOrgID": "o-1234567890"}
                        }
                    },
                ),
                "PASS",
            ),
            (
                "Invalid Condition Key in DenyOutsideOrganization",
                valid_policy,
                None,
                (
                    1,
                    {
                        "Condition": {
                            "StringNotEquals": {"aws:wrongKey": "o-1234567890"}
                        }
                    },
                ),
                "FAIL",
            ),
            (
                "Valid Condition Key in DenyOutsideOrganization",
                valid_policy,
                None,
                (
                    1,
                    {
                        "Condition": {
                            "StringNotEquals": {"aws:PrincipalOrgID": "o-1234567890"}
                        }
                    },
                ),
                "PASS",
            ),
            (
                "Invalid PrincipalOrgID in DenyOutsideOrganization",
                valid_policy,
                None,
                (
                    1,
                    {
                        "Condition": {
                            "StringNotEquals": {"aws:PrincipalOrgID": "o-invalid"}
                        }
                    },
                ),
                "FAIL",
            ),
            (
                "Valid PrincipalOrgID in DenyOutsideOrganization",
                valid_policy,
                None,
                (
                    1,
                    {
                        "Condition": {
                            "StringNotEquals": {"aws:PrincipalOrgID": "o-1234567890"}
                        }
                    },
                ),
                "PASS",
            ),
            # test modified statement AllowAuditPolicyRead
            (
                "Invalid wildcard in NotAction in AllowAuditPolicyRead",
                valid_policy,
                None,
                (2, {"NotAction": "*"}),
                "FAIL",
            ),
            (
                "No wildcard in NotAction in AllowAuditPolicyRead",
                valid_policy,
                None,
                (2, {"NotAction": "secretsmanager:DescribeSecret"}),
                "PASS",
            ),
            (
                "Invalid wildcard in NotAction in AllowSecretAccessForRole2",
                valid_policy,
                None,
                (3, {"NotAction": "*"}),
                "FAIL",
            ),
            (
                "No wildcard in NotAction in AllowSecretAccessForRole2",
                valid_policy,
                None,
                (3, {"NotAction": "secretsmanager:DescribeSecret"}),
                "PASS",
            ),
            (
                "Invalid wildcard in NotAction in both statements",
                valid_policy,
                None,
                [(2, {"NotAction": "*"}), (3, {"NotAction": "secretsmanager:*"})],
                "FAIL",
            ),
            (
                "No wildcard in NotAction in both statements",
                valid_policy,
                None,
                [
                    (2, {"NotAction": "secretsmanager:DescribeSecret"}),
                    (3, {"NotAction": "secretsmanager:GetSecretValue"}),
                ],
                "PASS",
            ),
            # test policy with removed statements
            ("Missing DenyUnauthorizedPrincipals", valid_policy, 0, None, "FAIL"),
            ("Missing DenyOutsideOrganization", valid_policy, 1, None, "FAIL"),
            # the following 2 test cases PASS because these statements are not required to make the Policy secure
            # but in practice the AWS Principal will not be able to access the secret
            ("Missing AllowAuditPolicyRead", valid_policy, 2, None, "PASS"),
            ("Missing AllowSecretAccessForRole2", valid_policy, 3, None, "PASS"),
        ]

        for (
            description,
            base_policy,
            remove_index,
            modify_element,
            expected_status,
        ) in test_cases:
            policy_copy = json.loads(json.dumps(base_policy))
            if remove_index is not None:
                del policy_copy["Statement"][remove_index]

            if modify_element is not None:
                if isinstance(modify_element, list):
                    for index, value in modify_element:
                        policy_copy["Statement"][index].update(value)
                else:
                    index, value = modify_element
                    policy_copy["Statement"][index].update(value)

            secretsmanager_client.put_resource_policy(
                SecretId=secret["ARN"], ResourcePolicy=json.dumps(policy_copy)
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

            with mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ), mock.patch(
                "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                new=SecretsManager(aws_provider),
            ), mock.patch(
                "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client.audit_config",
                {"organizations_trusted_ids": "o-1234567890"},
            ):
                from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                    secretsmanager_has_restrictive_resource_policy,
                )

                check = secretsmanager_has_restrictive_resource_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == expected_status, f"Test case: {description}"

    @mock_aws
    def test_secret_with_modified_restrictive_policies_for_services(self):
        secretsmanager_client = client(
            "secretsmanager", region_name=AWS_REGION_EU_WEST_1
        )
        secret = secretsmanager_client.create_secret(Name="test-secret-modified")

        valid_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyUnauthorizedPrincipals",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "StringNotEqualsIfExists": {
                            "aws:PrincipalArn": [
                                "arn:aws:iam::123456789012:role/AccountSecurityAuditRole",
                                "arn:aws:iam::123456789012:role/Role2",
                            ],
                            "aws:PrincipalServiceName": "appflow.amazonaws.com",
                        }
                    },
                },
                {
                    "Sid": "DenyOutsideOrganization",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "secretsmanager:*",
                    "Resource": "*",
                    "Condition": {
                        "StringNotEquals": {"aws:PrincipalOrgID": "o-1234567890"}
                    },
                },
                {
                    "Sid": "AllowAuditPolicyRead",
                    "Effect": "Deny",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:role/AccountSecurityAuditRole"
                    },
                    "NotAction": [
                        "secretsmanager:DescribeSecret",
                        "secretsmanager:GetResourcePolicy",
                    ],
                    "Resource": "*",
                },
                {
                    "Sid": "AllowSecretAccessForRole2",
                    "Effect": "Deny",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:role/Role2"},
                    "NotAction": ["secretsmanager:GetSecretValue"],
                    "Resource": "*",
                },
                {
                    "Sid": "AllowAppFlowAccess",
                    "Effect": "Allow",
                    "Principal": {"Service": "appflow.amazonaws.com"},
                    "Action": [
                        "secretsmanager:GetSecretValue",
                        "secretsmanager:PutSecretValue",
                        "secretsmanager:DeleteSecret",
                        "secretsmanager:DescribeSecret",
                        "secretsmanager:UpdateSecret",
                    ],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": "123456789012"}
                    },
                },
            ],
        }

        test_cases = [
            (
                "Valid unmodified Policy with PrincipalArn and Service",
                valid_policy,
                None,
                "PASS",
            ),
            (
                "Invalid wildcard '*' in Action in AllowAppFlowAccess",
                valid_policy,
                (4, {"Action": "*"}),
                "FAIL",
            ),
            (
                "No wildcard '*' in Action in AllowAppFlowAccess",
                valid_policy,
                (4, {"Action": "secretsmanager:GetSecretValue"}),
                "PASS",
            ),
            (
                "Invalid wildcard 'secretsmanager:*' in Action in AllowAppFlowAccess",
                valid_policy,
                (4, {"Action": "secretsmanager:*"}),
                "FAIL",
            ),
            (
                "No wildcard 'secretsmanager:*' in Action in AllowAppFlowAccess",
                valid_policy,
                (4, {"Action": "secretsmanager:ValidAction"}),
                "PASS",
            ),
            (
                "Missing Condition in AllowAppFlowAccess",
                valid_policy,
                (4, {"Condition": {}}),
                "FAIL",
            ),
            (
                "Valid Condition in AllowAppFlowAccess",
                valid_policy,
                (
                    4,
                    {
                        "Condition": {
                            "StringEquals": {"aws:SourceAccount": "123456789012"}
                        }
                    },
                ),
                "PASS",
            ),
            (
                "Invalid Condition Operator in AllowAppFlowAccess",
                valid_policy,
                (
                    4,
                    {
                        "Condition": {
                            "WrongOperator": {"aws:SourceAccount": "123456789012"}
                        }
                    },
                ),
                "FAIL",
            ),
            (
                "Valid Condition Operator in AllowAppFlowAccess",
                valid_policy,
                (
                    4,
                    {
                        "Condition": {
                            "StringEquals": {"aws:SourceAccount": "123456789012"}
                        }
                    },
                ),
                "PASS",
            ),
            (
                "Invalid Condition Key in AllowAppFlowAccess",
                valid_policy,
                (4, {"Condition": {"StringEquals": {"aws:WrongKey": "123456789012"}}}),
                "FAIL",
            ),
            (
                "Valid Condition Key in AllowAppFlowAccess",
                valid_policy,
                (
                    4,
                    {
                        "Condition": {
                            "StringEquals": {"aws:SourceAccount": "123456789012"}
                        }
                    },
                ),
                "PASS",
            ),
        ]

        for (
            description,
            base_policy,
            modify_element,
            expected_status,
        ) in test_cases:
            policy_copy = json.loads(json.dumps(base_policy))
            if modify_element is not None:
                if isinstance(modify_element, list):
                    for index, value in modify_element:
                        policy_copy["Statement"][index].update(value)
                else:
                    index, value = modify_element
                    policy_copy["Statement"][index].update(value)

            secretsmanager_client.put_resource_policy(
                SecretId=secret["ARN"], ResourcePolicy=json.dumps(policy_copy)
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

            with mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ), mock.patch(
                "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                new=SecretsManager(aws_provider),
            ), mock.patch(
                "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client.audit_config",
                {"organizations_trusted_ids": "o-1234567890"},
            ):
                from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                    secretsmanager_has_restrictive_resource_policy,
                )

                check = secretsmanager_has_restrictive_resource_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == expected_status, f"Test case: {description}"
