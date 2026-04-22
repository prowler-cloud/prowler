import json
import pytest
from unittest import mock
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.secretsmanager.secretsmanager_service import (
    SecretsManager,
)
from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)


@pytest.fixture(scope="function")
def secretsmanager_client():
    with mock_aws():
        client_instance = client("secretsmanager", region_name=AWS_REGION_EU_WEST_1)
        secret = client_instance.create_secret(Name="test-secret")
        yield client_instance, secret["ARN"]


class TestSecretsManagerHasRestrictiveResourcePolicy:

    def test_assumed_role_identity_arn_triggers_transformation(self):

        with mock_aws():
            boto3_client = client("secretsmanager", region_name=AWS_REGION_EU_WEST_1)
            boto3_client.create_secret(Name="mock-secret")
            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            sm_client = SecretsManager(aws_provider)
            sm_client.provider._assumed_role_configuration = None

            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch.object(
                    sm_client.provider.identity,
                    "identity_arn",
                    "arn:aws:sts::123456789012:assumed-role/TestRole/SessionName",
                ),
                mock.patch.object(
                    sm_client.provider, "_assumed_role_configuration", None
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                    sm_client,
                ),
            ):
                from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                    secretsmanager_has_restrictive_resource_policy,
                )

                check = secretsmanager_has_restrictive_resource_policy()
                result = check.execute()

                assert len(result) == 1
                assert (
                    "arn:aws:iam::123456789012:role/TestRole"
                    in result[0].status_extended
                )

    def test_non_assumed_role_identity_arn_remains_unchanged(self):
        with mock_aws():
            boto3_client = client("secretsmanager", region_name=AWS_REGION_EU_WEST_1)
            boto3_client.create_secret(Name="mock-secret")
            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            sm_client = SecretsManager(aws_provider)
            sm_client.provider._assumed_role_configuration = None

            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch.object(
                    sm_client.provider.identity,
                    "identity_arn",
                    "arn:aws:iam::123456789012:user/MyUser",
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                    sm_client,
                ),
            ):
                from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                    secretsmanager_has_restrictive_resource_policy,
                )

                check = secretsmanager_has_restrictive_resource_policy()
                result = check.execute()

                assert len(result) == 1
                assert (
                    "arn:aws:iam::123456789012:user/MyUser" in result[0].status_extended
                )

    def test_no_secrets(self):
        with mock_aws():
            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

            from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                secretsmanager_client,
            )

            secretsmanager_client.secrets.clear()

            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                    new=SecretsManager(aws_provider),
                ),
            ):
                from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                    secretsmanager_has_restrictive_resource_policy,
                )

                check = secretsmanager_has_restrictive_resource_policy()
                result = check.execute()

                assert len(result) == 0

    def test_secret_with_weak_policy(self, secretsmanager_client):
        client_instance, secret_arn = secretsmanager_client
        client_instance.put_resource_policy(
            SecretId=secret_arn,
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                new=SecretsManager(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                secretsmanager_has_restrictive_resource_policy,
            )

            check = secretsmanager_has_restrictive_resource_policy()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    @pytest.mark.parametrize(
        "description, remove_index, modify_element, expected_status",
        [
            # test unmodified policy
            ("Valid Policy", None, None, "PASS"),
            # test modified statement DenyUnauthorizedPrincipals
            (
                "Invalid Effect in DenyUnauthorizedPrincipals",
                None,
                (0, {"Effect": "Allow"}),
                "FAIL",
            ),
            (
                "Valid Effect in DenyUnauthorizedPrincipals",
                None,
                (0, {"Effect": "Deny"}),
                "PASS",
            ),
            (
                "Invalid Action in DenyUnauthorizedPrincipals",
                None,
                (0, {"Action": "InvalidAction"}),
                "FAIL",
            ),
            (
                "Valid Action in DenyUnauthorizedPrincipals",
                None,
                (0, {"Action": "*"}),
                "PASS",
            ),
            (
                "Invalid Resource in DenyUnauthorizedPrincipals",
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
                None,
                (0, {"Resource": "*"}),
                "PASS",
            ),
            (
                "Invalid Condition Operator in DenyUnauthorizedPrincipals",
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
                None,
                (
                    0,
                    {
                        "Condition": {
                            "StringNotEquals": {
                                "aws:PrincipalServiceName": "appflow.amazonaws.com"
                            }
                        }
                    },
                ),
                "FAIL",
            ),
            (
                "Invalid Condition Operator for Principal in DenyUnauthorizedPrincipals",
                None,
                (
                    0,
                    {
                        "Condition": {
                            "StringNotEqualsIfExists": {
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/AccountSecurityAuditRole"
                            }
                        }
                    },
                ),
                "FAIL",
            ),
            # test modified statement DenyOutsideOrganization
            (
                "Invalid Effect in DenyOutsideOrganization",
                None,
                (1, {"Effect": "Allow"}),
                "FAIL",
            ),
            (
                "Valid Effect in DenyOutsideOrganization",
                None,
                (1, {"Effect": "Deny"}),
                "PASS",
            ),
            (
                "Invalid Action in DenyOutsideOrganization",
                None,
                (1, {"Action": "secretsmanager:InvalidAction"}),
                "FAIL",
            ),
            (
                "Valid Action in DenyOutsideOrganization",
                None,
                (1, {"Action": "secretsmanager:*"}),
                "PASS",
            ),
            (
                "Invalid Resource in DenyOutsideOrganization",
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
                "Invalid multiple Condition Operators in DenyOutsideOrganization",
                None,
                (
                    1,
                    {
                        "Condition": {
                            "StringNotEquals": {"aws:PrincipalOrgID": "o-1234567890"},
                            "StringNotEqualsIfExists": {
                                "aws:PrincipalOrgID": "o-1234567890"
                            },
                        }
                    },
                ),
                "FAIL",
            ),
            (
                "Invalid multiple keys in StringNotEquals Condition in DenyOutsideOrganization",
                None,
                (
                    1,
                    {
                        "Condition": {
                            "StringNotEquals": {
                                "aws:PrincipalOrgID": "o-1234567890",
                                "aws:PrincipalServiceName": "appflow.amazonaws.com",
                            }
                        }
                    },
                ),
                "FAIL",
            ),
            # test modified statement AllowAuditPolicyRead
            (
                "Invalid wildcard in NotAction in AllowAuditPolicyRead",
                None,
                (2, {"NotAction": "*"}),
                "FAIL",
            ),
            (
                "No wildcard in NotAction in AllowAuditPolicyRead",
                None,
                (2, {"NotAction": "secretsmanager:DescribeSecret"}),
                "PASS",
            ),
            (
                "Invalid wildcard in NotAction in AllowSecretAccessForRole2",
                None,
                (3, {"NotAction": "*"}),
                "FAIL",
            ),
            (
                "No wildcard in NotAction in AllowSecretAccessForRole2",
                None,
                (3, {"NotAction": "secretsmanager:DescribeSecret"}),
                "PASS",
            ),
            (
                "Invalid wildcard in NotAction in both statements",
                None,
                [
                    (2, {"NotAction": "*"}),
                    (3, {"NotAction": "secretsmanager:*"}),
                ],
                "FAIL",
            ),
            (
                "No wildcard in NotAction in both statements",
                None,
                [
                    (2, {"NotAction": "secretsmanager:DescribeSecret"}),
                    (3, {"NotAction": "secretsmanager:GetSecretValue"}),
                ],
                "PASS",
            ),
            # test policy with removed statements
            ("Missing DenyUnauthorizedPrincipals", 0, None, "FAIL"),
            ("Missing DenyOutsideOrganization", 1, None, "FAIL"),
            # the following 2 test cases PASS because these statements are not required to make the Policy secure
            # but in practice the AWS Principal will not be able to access the secret
            ("Missing AllowAuditPolicyRead", 2, None, "PASS"),
            ("Missing AllowSecretAccessForRole2", 3, None, "PASS"),
        ],
    )
    def test_secretsmanager_policies_for_principals(
        self,
        secretsmanager_client,
        description,
        remove_index,
        modify_element,
        expected_status,
    ):
        with mock_aws():
            client_instance, secret_arn = secretsmanager_client

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

            policy_copy = json.loads(json.dumps(valid_policy))
            if remove_index is not None:
                del policy_copy["Statement"][remove_index]
            if modify_element is not None:
                if isinstance(modify_element, list):
                    for index, value in modify_element:
                        policy_copy["Statement"][index].update(value)
                else:
                    index, value = modify_element
                    policy_copy["Statement"][index].update(value)

            client_instance.put_resource_policy(
                SecretId=secret_arn, ResourcePolicy=json.dumps(policy_copy)
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                    new=SecretsManager(aws_provider),
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client.audit_config",
                    {"organizations_trusted_ids": "o-1234567890"},
                ),
            ):
                from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                    secretsmanager_has_restrictive_resource_policy,
                )

                check = secretsmanager_has_restrictive_resource_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == expected_status, f"Test case '{description}'"

    @pytest.mark.parametrize(
        "description, modify_element, expected_status",
        [
            # test unmodified policy
            (
                "Valid unmodified Policy with PrincipalArn and Service",
                None,
                "PASS",
            ),
            # test statement DenyUnauthorizedPrincipals
            (
                "Missing Null Condition",
                (
                    0,
                    {
                        "Condition": {
                            "StringNotEqualsIfExists": {
                                "aws:PrincipalArn": [
                                    "arn:aws:iam::123456789012:role/AccountSecurityAuditRole",
                                    "arn:aws:iam::123456789012:role/Role2",
                                ],
                                "aws:PrincipalServiceName": "appflow.amazonaws.com",
                            }
                        }
                    },
                ),
                "FAIL",
            ),
            (
                "Missing PrincipalArn in Null Condition",
                (
                    0,
                    {
                        "Condition": {
                            "StringNotEqualsIfExists": {
                                "aws:PrincipalArn": [
                                    "arn:aws:iam::123456789012:role/AccountSecurityAuditRole",
                                    "arn:aws:iam::123456789012:role/Role2",
                                ],
                                "aws:PrincipalServiceName": "appflow.amazonaws.com",
                            },
                            "Null": {"aws:PrincipalServiceName": "true"},
                        }
                    },
                ),
                "FAIL",
            ),
            (
                "Invalid value for PrincipalArn in Null Condition",
                (
                    0,
                    {
                        "Condition": {
                            "StringNotEqualsIfExists": {
                                "aws:PrincipalArn": [
                                    "arn:aws:iam::123456789012:role/AccountSecurityAuditRole",
                                    "arn:aws:iam::123456789012:role/Role2",
                                ],
                                "aws:PrincipalServiceName": "appflow.amazonaws.com",
                            },
                            "Null": {
                                "aws:PrincipalArn": "false",
                                "aws:PrincipalServiceName": "true",
                            },
                        }
                    },
                ),
                "FAIL",
            ),
            # test statement DenyOutsideOrganization
            (
                "Invalid DenyOutsideOrganization using Principal with disallowed service",
                (1, {"Principal": {"Service": "invalid.service.com"}}),
                "FAIL",
            ),
            # test statement AllowAppFlowAccess
            (
                "Invalid wildcard '*' in Action in AllowAppFlowAccess",
                (4, {"Action": "*"}),
                "FAIL",
            ),
            (
                "No wildcard '*' in Action in AllowAppFlowAccess",
                (4, {"Action": "secretsmanager:GetSecretValue"}),
                "PASS",
            ),
            (
                "Invalid wildcard 'secretsmanager:*' in Action in AllowAppFlowAccess",
                (4, {"Action": "secretsmanager:*"}),
                "FAIL",
            ),
            (
                "No wildcard 'secretsmanager:*' in Action in AllowAppFlowAccess",
                (4, {"Action": "secretsmanager:ValidAction"}),
                "PASS",
            ),
            (
                "Missing Condition in AllowAppFlowAccess",
                (4, {"Condition": {}}),
                "FAIL",
            ),
            (
                "Valid Condition in AllowAppFlowAccess",
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
                (
                    4,
                    {"Condition": {"StringEquals": {"aws:WrongKey": "123456789012"}}},
                ),
                "FAIL",
            ),
            (
                "Valid Condition Key in AllowAppFlowAccess",
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
        ],
    )
    def test_secretsmanager_policies_for_principals_and_services(
        self,
        secretsmanager_client,
        description,
        modify_element,
        expected_status,
    ):
        with mock_aws():
            client_instance, secret_arn = secretsmanager_client

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
                            },
                            "Null": {
                                "aws:PrincipalArn": "true",
                                "aws:PrincipalServiceName": "true",
                            },
                        },
                    },
                    {
                        "Sid": "DenyOutsideOrganization",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "secretsmanager:*",
                        "Resource": "*",
                        "Condition": {
                            "StringNotEquals": {
                                "aws:PrincipalOrgID": "o-1234567890",
                                "aws:PrincipalServiceName": "appflow.amazonaws.com",
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

            policy_copy = json.loads(json.dumps(valid_policy))

            if modify_element is not None:
                if isinstance(modify_element, list):
                    for index, value in modify_element:
                        policy_copy["Statement"][index].update(value)
                else:
                    index, value = modify_element
                    policy_copy["Statement"][index].update(value)

            client_instance.put_resource_policy(
                SecretId=secret_arn, ResourcePolicy=json.dumps(policy_copy)
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                    new=SecretsManager(aws_provider),
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client.audit_config",
                    {"organizations_trusted_ids": "o-1234567890"},
                ),
            ):
                from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                    secretsmanager_has_restrictive_resource_policy,
                )

                check = secretsmanager_has_restrictive_resource_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == expected_status, f"Test case: {description}"

    def test_assumed_role_configuration_with_valid_role_arn(self):
        with mock_aws():
            boto3_client = client("secretsmanager", region_name=AWS_REGION_EU_WEST_1)
            boto3_client.create_secret(Name="mock-secret")
            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            sm_client = SecretsManager(aws_provider)

            mock_role_config = mock.MagicMock()
            mock_role_config.info.role_arn.arn = (
                "arn:aws:iam::123456789012:role/AssumedRole"
            )

            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch.object(
                    sm_client.provider,
                    "_assumed_role_configuration",
                    mock_role_config,
                    create=True,
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                    sm_client,
                ),
            ):
                from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                    secretsmanager_has_restrictive_resource_policy,
                )

                check = secretsmanager_has_restrictive_resource_policy()
                result = check.execute()

                assert len(result) == 1
                assert (
                    "arn:aws:iam::123456789012:role/AssumedRole"
                    in result[0].status_extended
                )

    def test_identity_arn_none_fallback(self):
        with mock_aws():
            boto3_client = client("secretsmanager", region_name=AWS_REGION_EU_WEST_1)
            boto3_client.create_secret(Name="mock-secret")
            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            sm_client = SecretsManager(aws_provider)
            sm_client.provider._assumed_role_configuration = None

            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch.object(
                    sm_client.provider.identity,
                    "identity_arn",
                    None,
                ),
                mock.patch.object(
                    sm_client.provider, "_assumed_role_configuration", None
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                    sm_client,
                ),
            ):
                from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                    secretsmanager_has_restrictive_resource_policy,
                )

                check = secretsmanager_has_restrictive_resource_policy()
                result = check.execute()

                assert len(result) == 1
                assert "'None'" in result[0].status_extended

    def test_cross_account_principal_in_allow_statement(self, secretsmanager_client):
        with mock_aws():
            client_instance, secret_arn = secretsmanager_client

            policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AllowCrossAccountAccess",
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "arn:aws:iam::999999999999:role/ExternalRole"
                        },
                        "Action": "secretsmanager:GetSecretValue",
                        "Resource": "*",
                    },
                    {
                        "Sid": "DenyUnauthorizedPrincipals",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "*",
                        "Resource": "*",
                        "Condition": {
                            "StringNotEquals": {
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/MyRole"
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
                        "Sid": "DenyNotAction",
                        "Effect": "Deny",
                        "Principal": {"AWS": "arn:aws:iam::123456789012:role/MyRole"},
                        "NotAction": ["secretsmanager:DescribeSecret"],
                        "Resource": "*",
                    },
                ],
            }

            client_instance.put_resource_policy(
                SecretId=secret_arn, ResourcePolicy=json.dumps(policy)
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                    new=SecretsManager(aws_provider),
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client.audit_config",
                    {"organizations_trusted_ids": "o-1234567890"},
                ),
            ):
                from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                    secretsmanager_has_restrictive_resource_policy,
                )

                check = secretsmanager_has_restrictive_resource_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert "Cross-account access detected" in result[0].status_extended
                assert (
                    "arn:aws:iam::999999999999:role/ExternalRole"
                    in result[0].status_extended
                )

    def test_multiple_cross_account_principals_truncation(self, secretsmanager_client):
        with mock_aws():
            client_instance, secret_arn = secretsmanager_client

            policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AllowCrossAccount1",
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::111111111111:role/Role1"},
                        "Action": "secretsmanager:GetSecretValue",
                        "Resource": "*",
                    },
                    {
                        "Sid": "AllowCrossAccount2",
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::222222222222:role/Role2"},
                        "Action": "secretsmanager:GetSecretValue",
                        "Resource": "*",
                    },
                    {
                        "Sid": "AllowCrossAccount3",
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::333333333333:role/Role3"},
                        "Action": "secretsmanager:GetSecretValue",
                        "Resource": "*",
                    },
                    {
                        "Sid": "AllowCrossAccount4",
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::444444444444:role/Role4"},
                        "Action": "secretsmanager:GetSecretValue",
                        "Resource": "*",
                    },
                    {
                        "Sid": "DenyUnauthorizedPrincipals",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "*",
                        "Resource": "*",
                        "Condition": {
                            "StringNotEquals": {
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/MyRole"
                            }
                        },
                    },
                ],
            }

            client_instance.put_resource_policy(
                SecretId=secret_arn, ResourcePolicy=json.dumps(policy)
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                    new=SecretsManager(aws_provider),
                ),
            ):
                from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                    secretsmanager_has_restrictive_resource_policy,
                )

                check = secretsmanager_has_restrictive_resource_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert "Cross-account access detected" in result[0].status_extended
                assert "and more..." in result[0].status_extended

    def test_wildcard_principal_in_allow_with_restrictive_condition(
        self, secretsmanager_client
    ):
        with mock_aws():
            client_instance, secret_arn = secretsmanager_client

            policy = {
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
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/MyRole"
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
                        "Sid": "AllowWithRestrictiveCondition",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "secretsmanager:GetSecretValue",
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {"aws:PrincipalAccount": "123456789012"}
                        },
                    },
                    {
                        "Sid": "DenyNotAction",
                        "Effect": "Deny",
                        "Principal": {"AWS": "arn:aws:iam::123456789012:role/MyRole"},
                        "NotAction": ["secretsmanager:DescribeSecret"],
                        "Resource": "*",
                    },
                ],
            }

            client_instance.put_resource_policy(
                SecretId=secret_arn, ResourcePolicy=json.dumps(policy)
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                    new=SecretsManager(aws_provider),
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client.audit_config",
                    {"organizations_trusted_ids": "o-1234567890"},
                ),
            ):
                from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                    secretsmanager_has_restrictive_resource_policy,
                )

                check = secretsmanager_has_restrictive_resource_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert "Cross-account" not in result[0].status_extended

    @pytest.mark.parametrize(
        "description, arn_not_like_value, include_arn_like_statement, expected_status, expected_message",
        [
            (
                "Valid ArnNotLike with matching ArnLike",
                "arn:aws:iam::123456789012:role/LongPrefixRole*",
                True,
                "PASS",
                "sufficiently restrictive",
            ),
            (
                "Invalid ArnNotLike with short prefix",
                "arn:aws:iam::123456789012:role/Sho*",
                True,
                "FAIL",
                "does not meet all required restrictions",
            ),
            (
                "Valid ArnNotLike but missing ArnLike statement",
                "arn:aws:iam::123456789012:role/LongPrefixRole*",
                False,
                "FAIL",
                "Missing or incorrect 'ArnLike' validation",
            ),
        ],
    )
    def test_policy_with_arn_not_like(
        self,
        secretsmanager_client,
        description,
        arn_not_like_value,
        include_arn_like_statement,
        expected_status,
        expected_message,
    ):
        with mock_aws():
            client_instance, secret_arn = secretsmanager_client

            statements = [
                {
                    "Sid": "DenyUnauthorizedPrincipals",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "StringNotEquals": {
                            "aws:PrincipalArn": "arn:aws:iam::123456789012:role/AccountSecurityAuditRole"
                        },
                        "ArnNotLike": {"aws:PrincipalArn": arn_not_like_value},
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
            ]

            if include_arn_like_statement:
                statements.append(
                    {
                        "Sid": "DenyWildcardPrincipals",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "*",
                        "Resource": "*",
                        "Condition": {
                            "ArnLike": {"aws:PrincipalArn": arn_not_like_value}
                        },
                    }
                )

            policy = {
                "Version": "2012-10-17",
                "Statement": statements,
            }

            client_instance.put_resource_policy(
                SecretId=secret_arn, ResourcePolicy=json.dumps(policy)
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                    new=SecretsManager(aws_provider),
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client.audit_config",
                    {"organizations_trusted_ids": "o-1234567890"},
                ),
            ):
                from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                    secretsmanager_has_restrictive_resource_policy,
                )

                check = secretsmanager_has_restrictive_resource_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == expected_status, f"Test case: {description}"
                assert (
                    expected_message in result[0].status_extended
                ), f"Test case: {description}"

    def test_resource_as_list_with_matching_arn(self, secretsmanager_client):
        with mock_aws():
            client_instance, secret_arn = secretsmanager_client

            policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "DenyUnauthorizedPrincipals",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "*",
                        "Resource": [secret_arn],
                        "Condition": {
                            "StringNotEquals": {
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/MyRole"
                            }
                        },
                    },
                    {
                        "Sid": "DenyOutsideOrganization",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "secretsmanager:*",
                        "Resource": [secret_arn],
                        "Condition": {
                            "StringNotEquals": {"aws:PrincipalOrgID": "o-1234567890"}
                        },
                    },
                    {
                        "Sid": "DenyNotAction",
                        "Effect": "Deny",
                        "Principal": {"AWS": "arn:aws:iam::123456789012:role/MyRole"},
                        "NotAction": ["secretsmanager:DescribeSecret"],
                        "Resource": "*",
                    },
                ],
            }

            client_instance.put_resource_policy(
                SecretId=secret_arn, ResourcePolicy=json.dumps(policy)
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                    new=SecretsManager(aws_provider),
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client.audit_config",
                    {"organizations_trusted_ids": "o-1234567890"},
                ),
            ):
                from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                    secretsmanager_has_restrictive_resource_policy,
                )

                check = secretsmanager_has_restrictive_resource_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"

    def test_resource_as_list_with_nonmatching_arn(self, secretsmanager_client):
        with mock_aws():
            client_instance, secret_arn = secretsmanager_client

            policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "DenyUnauthorizedPrincipals",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "*",
                        "Resource": [
                            "arn:aws:secretsmanager:eu-west-1:123456789012:secret:wrong-secret"
                        ],
                        "Condition": {
                            "StringNotEquals": {
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/MyRole"
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
                ],
            }

            client_instance.put_resource_policy(
                SecretId=secret_arn, ResourcePolicy=json.dumps(policy)
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                    new=SecretsManager(aws_provider),
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client.audit_config",
                    {"organizations_trusted_ids": "o-1234567890"},
                ),
            ):
                from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                    secretsmanager_has_restrictive_resource_policy,
                )

                check = secretsmanager_has_restrictive_resource_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"

    def test_cross_account_allow_after_deny_is_detected(self, secretsmanager_client):
        """Regression: cross-account Allow placed after the Deny must still FAIL."""
        with mock_aws():
            client_instance, secret_arn = secretsmanager_client

            policy = {
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
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/MyRole"
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
                        "Sid": "AllowCrossAccountAfterDeny",
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "arn:aws:iam::999999999999:role/ExternalRole"
                        },
                        "Action": "secretsmanager:GetSecretValue",
                        "Resource": "*",
                    },
                ],
            }

            client_instance.put_resource_policy(
                SecretId=secret_arn, ResourcePolicy=json.dumps(policy)
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                    new=SecretsManager(aws_provider),
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client.audit_config",
                    {"organizations_trusted_ids": "o-1234567890"},
                ),
            ):
                from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                    secretsmanager_has_restrictive_resource_policy,
                )

                check = secretsmanager_has_restrictive_resource_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert "Cross-account access detected" in result[0].status_extended

    def test_service_allow_with_extra_restrictive_conditions_passes(
        self, secretsmanager_client
    ):
        """Service Allow with additional restrictive conditions (e.g. ArnLike) should PASS."""
        with mock_aws():
            client_instance, secret_arn = secretsmanager_client

            policy = {
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
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/MyRole",
                                "aws:PrincipalServiceName": "appflow.amazonaws.com",
                            },
                            "Null": {
                                "aws:PrincipalArn": "true",
                                "aws:PrincipalServiceName": "true",
                            },
                        },
                    },
                    {
                        "Sid": "DenyOutsideOrganization",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "secretsmanager:*",
                        "Resource": "*",
                        "Condition": {
                            "StringNotEquals": {
                                "aws:PrincipalOrgID": "o-1234567890",
                                "aws:PrincipalServiceName": "appflow.amazonaws.com",
                            }
                        },
                    },
                    {
                        "Sid": "AllowAppFlowAccess",
                        "Effect": "Allow",
                        "Principal": {"Service": "appflow.amazonaws.com"},
                        "Action": ["secretsmanager:GetSecretValue"],
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {"aws:SourceAccount": "123456789012"},
                            "ArnLike": {
                                "aws:SourceArn": "arn:aws:appflow:*:123456789012:*"
                            },
                        },
                    },
                ],
            }

            client_instance.put_resource_policy(
                SecretId=secret_arn, ResourcePolicy=json.dumps(policy)
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                    new=SecretsManager(aws_provider),
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client.audit_config",
                    {"organizations_trusted_ids": "o-1234567890"},
                ),
            ):
                from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                    secretsmanager_has_restrictive_resource_policy,
                )

                check = secretsmanager_has_restrictive_resource_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"

    def test_regionalized_service_principal_is_accepted(self, secretsmanager_client):
        """Regionalized service principals like logs.eu-central-1.amazonaws.com should be accepted."""
        with mock_aws():
            client_instance, secret_arn = secretsmanager_client

            policy = {
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
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/MyRole",
                                "aws:PrincipalServiceName": "logs.eu-central-1.amazonaws.com",
                            },
                            "Null": {
                                "aws:PrincipalArn": "true",
                                "aws:PrincipalServiceName": "true",
                            },
                        },
                    },
                    {
                        "Sid": "DenyOutsideOrganization",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "secretsmanager:*",
                        "Resource": "*",
                        "Condition": {
                            "StringNotEquals": {
                                "aws:PrincipalOrgID": "o-1234567890",
                                "aws:PrincipalServiceName": "logs.eu-central-1.amazonaws.com",
                            }
                        },
                    },
                    {
                        "Sid": "AllowLogsAccess",
                        "Effect": "Allow",
                        "Principal": {"Service": "logs.eu-central-1.amazonaws.com"},
                        "Action": ["secretsmanager:GetSecretValue"],
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {"aws:SourceAccount": "123456789012"}
                        },
                    },
                ],
            }

            client_instance.put_resource_policy(
                SecretId=secret_arn, ResourcePolicy=json.dumps(policy)
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                    new=SecretsManager(aws_provider),
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client.audit_config",
                    {"organizations_trusted_ids": "o-1234567890"},
                ),
            ):
                from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                    secretsmanager_has_restrictive_resource_policy,
                )

                check = secretsmanager_has_restrictive_resource_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"

    def test_single_statement_dict_not_list(self, secretsmanager_client):
        """Statement as a single dict (not wrapped in a list) must not crash."""
        with mock_aws():
            client_instance, secret_arn = secretsmanager_client

            # Policy with Statement as a single object instead of an array
            policy = {
                "Version": "2012-10-17",
                "Statement": {
                    "Sid": "DenyAll",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "*",
                    "Resource": "*",
                },
            }

            client_instance.put_resource_policy(
                SecretId=secret_arn, ResourcePolicy=json.dumps(policy)
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                    new=SecretsManager(aws_provider),
                ),
            ):
                from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                    secretsmanager_has_restrictive_resource_policy,
                )

                check = secretsmanager_has_restrictive_resource_policy()
                result = check.execute()

                # Single Deny-all without proper conditions -> FAIL, but must not crash
                assert len(result) == 1
                assert result[0].status == "FAIL"

    def test_service_allow_with_not_action_fails(self, secretsmanager_client):
        """Service Allow using NotAction instead of Action must FAIL."""
        with mock_aws():
            client_instance, secret_arn = secretsmanager_client

            policy = {
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
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/MyRole",
                                "aws:PrincipalServiceName": "appflow.amazonaws.com",
                            },
                            "Null": {
                                "aws:PrincipalArn": "true",
                                "aws:PrincipalServiceName": "true",
                            },
                        },
                    },
                    {
                        "Sid": "DenyOutsideOrganization",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "secretsmanager:*",
                        "Resource": "*",
                        "Condition": {
                            "StringNotEquals": {
                                "aws:PrincipalOrgID": "o-1234567890",
                                "aws:PrincipalServiceName": "appflow.amazonaws.com",
                            }
                        },
                    },
                    {
                        "Sid": "AllowAppFlowAccessWithNotAction",
                        "Effect": "Allow",
                        "Principal": {"Service": "appflow.amazonaws.com"},
                        "NotAction": "secretsmanager:DeleteSecret",
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {"aws:SourceAccount": "123456789012"}
                        },
                    },
                ],
            }

            client_instance.put_resource_policy(
                SecretId=secret_arn, ResourcePolicy=json.dumps(policy)
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                    new=SecretsManager(aws_provider),
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client.audit_config",
                    {"organizations_trusted_ids": "o-1234567890"},
                ),
            ):
                from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                    secretsmanager_has_restrictive_resource_policy,
                )

                check = secretsmanager_has_restrictive_resource_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert "NotAction" in result[0].status_extended

    def test_service_allow_missing_action_field_fails(self, secretsmanager_client):
        """Service Allow with no Action field at all must FAIL."""
        with mock_aws():
            client_instance, secret_arn = secretsmanager_client

            policy = {
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
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/MyRole",
                                "aws:PrincipalServiceName": "appflow.amazonaws.com",
                            },
                            "Null": {
                                "aws:PrincipalArn": "true",
                                "aws:PrincipalServiceName": "true",
                            },
                        },
                    },
                    {
                        "Sid": "DenyOutsideOrganization",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "secretsmanager:*",
                        "Resource": "*",
                        "Condition": {
                            "StringNotEquals": {
                                "aws:PrincipalOrgID": "o-1234567890",
                                "aws:PrincipalServiceName": "appflow.amazonaws.com",
                            }
                        },
                    },
                    {
                        "Sid": "AllowAppFlowAccessWithoutAction",
                        "Effect": "Allow",
                        "Principal": {"Service": "appflow.amazonaws.com"},
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {"aws:SourceAccount": "123456789012"}
                        },
                    },
                ],
            }

            client_instance.put_resource_policy(
                SecretId=secret_arn, ResourcePolicy=json.dumps(policy)
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                    new=SecretsManager(aws_provider),
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client.audit_config",
                    {"organizations_trusted_ids": "o-1234567890"},
                ),
            ):
                from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                    secretsmanager_has_restrictive_resource_policy,
                )

                check = secretsmanager_has_restrictive_resource_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert "missing Action field" in result[0].status_extended

    def test_service_allow_with_not_resource_fails(self, secretsmanager_client):
        """Service Allow using NotResource instead of Resource must FAIL."""
        with mock_aws():
            client_instance, secret_arn = secretsmanager_client

            policy = {
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
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/MyRole",
                                "aws:PrincipalServiceName": "appflow.amazonaws.com",
                            },
                            "Null": {
                                "aws:PrincipalArn": "true",
                                "aws:PrincipalServiceName": "true",
                            },
                        },
                    },
                    {
                        "Sid": "DenyOutsideOrganization",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "secretsmanager:*",
                        "Resource": "*",
                        "Condition": {
                            "StringNotEquals": {
                                "aws:PrincipalOrgID": "o-1234567890",
                                "aws:PrincipalServiceName": "appflow.amazonaws.com",
                            }
                        },
                    },
                    {
                        "Sid": "AllowAppFlowAccessWithNotResource",
                        "Effect": "Allow",
                        "Principal": {"Service": "appflow.amazonaws.com"},
                        "Action": "secretsmanager:GetSecretValue",
                        "NotResource": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:other-secret",
                        "Condition": {
                            "StringEquals": {"aws:SourceAccount": "123456789012"}
                        },
                    },
                ],
            }

            client_instance.put_resource_policy(
                SecretId=secret_arn, ResourcePolicy=json.dumps(policy)
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                    new=SecretsManager(aws_provider),
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client.audit_config",
                    {"organizations_trusted_ids": "o-1234567890"},
                ),
            ):
                from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                    secretsmanager_has_restrictive_resource_policy,
                )

                check = secretsmanager_has_restrictive_resource_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert "NotResource" in result[0].status_extended

    def test_condition_keys_case_insensitive_principals_only(
        self, secretsmanager_client
    ):
        """Condition keys with non-canonical casing must still be recognized."""
        with mock_aws():
            client_instance, secret_arn = secretsmanager_client

            # Policy uses non-canonical casing for all condition keys
            policy = {
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
                                "AWS:PrincipalArn": [
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
                            "StringNotEquals": {"AWS:PrincipalOrgID": "o-1234567890"}
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

            client_instance.put_resource_policy(
                SecretId=secret_arn, ResourcePolicy=json.dumps(policy)
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                    new=SecretsManager(aws_provider),
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client.audit_config",
                    {"organizations_trusted_ids": "o-1234567890"},
                ),
            ):
                from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                    secretsmanager_has_restrictive_resource_policy,
                )

                check = secretsmanager_has_restrictive_resource_policy()
                result = check.execute()

                assert len(result) == 1
                assert (
                    result[0].status == "PASS"
                ), f"Policy with uppercase condition keys should PASS but got: {result[0].status_extended}"

    def test_condition_keys_case_insensitive_with_services(self, secretsmanager_client):
        """Mixed-case condition keys with service principals must still PASS."""
        with mock_aws():
            client_instance, secret_arn = secretsmanager_client

            policy = {
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
                                "AWS:PrincipalArn": "arn:aws:iam::123456789012:role/MyRole",
                                "AWS:PrincipalServiceName": "appflow.amazonaws.com",
                            },
                            "Null": {
                                "AWS:PrincipalArn": "true",
                                "AWS:PrincipalServiceName": "true",
                            },
                        },
                    },
                    {
                        "Sid": "DenyOutsideOrganization",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "secretsmanager:*",
                        "Resource": "*",
                        "Condition": {
                            "StringNotEquals": {
                                "AWS:PrincipalOrgID": "o-1234567890",
                                "AWS:PrincipalServiceName": "appflow.amazonaws.com",
                            }
                        },
                    },
                    {
                        "Sid": "AllowAppFlowAccess",
                        "Effect": "Allow",
                        "Principal": {"Service": "appflow.amazonaws.com"},
                        "Action": ["secretsmanager:GetSecretValue"],
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {"AWS:SourceAccount": "123456789012"}
                        },
                    },
                ],
            }

            client_instance.put_resource_policy(
                SecretId=secret_arn, ResourcePolicy=json.dumps(policy)
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                    new=SecretsManager(aws_provider),
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client.audit_config",
                    {"organizations_trusted_ids": "o-1234567890"},
                ),
            ):
                from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                    secretsmanager_has_restrictive_resource_policy,
                )

                check = secretsmanager_has_restrictive_resource_policy()
                result = check.execute()

                assert len(result) == 1
                assert (
                    result[0].status == "PASS"
                ), f"Policy with mixed-case condition keys should PASS but got: {result[0].status_extended}"

    def test_mixed_principal_allow_must_validate_service(self, secretsmanager_client):
        """Allow with both AWS and Service principals must validate the service principal."""
        with mock_aws():
            client_instance, secret_arn = secretsmanager_client

            # The Allow statement has a mixed Principal with both AWS and Service.
            # The service principal must still be validated for aws:SourceAccount.
            # Without the fix, extract_field() only returned the AWS branch,
            # silently skipping service validation.
            policy = {
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
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/MyRole",
                                "aws:PrincipalServiceName": "appflow.amazonaws.com",
                            },
                            "Null": {
                                "aws:PrincipalArn": "true",
                                "aws:PrincipalServiceName": "true",
                            },
                        },
                    },
                    {
                        "Sid": "DenyOutsideOrganization",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "secretsmanager:*",
                        "Resource": "*",
                        "Condition": {
                            "StringNotEquals": {
                                "aws:PrincipalOrgID": "o-1234567890",
                                "aws:PrincipalServiceName": "appflow.amazonaws.com",
                            }
                        },
                    },
                    {
                        "Sid": "AllowMixedPrincipalWithoutSourceAccount",
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "arn:aws:iam::123456789012:role/MyRole",
                            "Service": "appflow.amazonaws.com",
                        },
                        "Action": ["secretsmanager:GetSecretValue"],
                        "Resource": "*",
                    },
                ],
            }

            client_instance.put_resource_policy(
                SecretId=secret_arn, ResourcePolicy=json.dumps(policy)
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                    new=SecretsManager(aws_provider),
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client.audit_config",
                    {"organizations_trusted_ids": "o-1234567890"},
                ),
            ):
                from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                    secretsmanager_has_restrictive_resource_policy,
                )

                check = secretsmanager_has_restrictive_resource_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    "missing Condition block" in result[0].status_extended
                ), f"Mixed-principal Allow without SourceAccount should FAIL but got: {result[0].status_extended}"

    def test_source_account_as_list_passes(self, secretsmanager_client):
        """aws:SourceAccount as a single-value list must be accepted."""
        with mock_aws():
            client_instance, secret_arn = secretsmanager_client

            policy = {
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
                                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/MyRole",
                                "aws:PrincipalServiceName": "appflow.amazonaws.com",
                            },
                            "Null": {
                                "aws:PrincipalArn": "true",
                                "aws:PrincipalServiceName": "true",
                            },
                        },
                    },
                    {
                        "Sid": "DenyOutsideOrganization",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "secretsmanager:*",
                        "Resource": "*",
                        "Condition": {
                            "StringNotEquals": {
                                "aws:PrincipalOrgID": "o-1234567890",
                                "aws:PrincipalServiceName": "appflow.amazonaws.com",
                            }
                        },
                    },
                    {
                        "Sid": "AllowAppFlowAccess",
                        "Effect": "Allow",
                        "Principal": {"Service": "appflow.amazonaws.com"},
                        "Action": ["secretsmanager:GetSecretValue"],
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {"aws:SourceAccount": ["123456789012"]}
                        },
                    },
                ],
            }

            client_instance.put_resource_policy(
                SecretId=secret_arn, ResourcePolicy=json.dumps(policy)
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client",
                    new=SecretsManager(aws_provider),
                ),
                mock.patch(
                    "prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy.secretsmanager_client.audit_config",
                    {"organizations_trusted_ids": "o-1234567890"},
                ),
            ):
                from prowler.providers.aws.services.secretsmanager.secretsmanager_has_restrictive_resource_policy.secretsmanager_has_restrictive_resource_policy import (
                    secretsmanager_has_restrictive_resource_policy,
                )

                check = secretsmanager_has_restrictive_resource_policy()
                result = check.execute()

                assert len(result) == 1
                assert (
                    result[0].status == "PASS"
                ), f"SourceAccount as list should PASS but got: {result[0].status_extended}"
