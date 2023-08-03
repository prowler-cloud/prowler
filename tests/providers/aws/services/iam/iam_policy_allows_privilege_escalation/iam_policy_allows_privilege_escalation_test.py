from json import dumps
from re import search
from unittest import mock

from boto3 import client, session
from moto import mock_iam

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_REGION = "us-east-1"
AWS_ACCOUNT_NUMBER = "123456789012"

# Keep this up-to-date with the check's actions that allows for privilege escalation
privilege_escalation_policies_combination = {
    "CreatePolicyVersion": {"iam:CreatePolicyVersion"},
    "SetDefaultPolicyVersion": {"iam:SetDefaultPolicyVersion"},
    "iam:PassRole": {"iam:PassRole"},
    "PassRole+EC2": {
        "iam:PassRole",
        "ec2:RunInstances",
    },
    "PassRole+CreateLambda+Invoke": {
        "iam:PassRole",
        "lambda:CreateFunction",
        "lambda:InvokeFunction",
    },
    "PassRole+CreateLambda+ExistingDynamo": {
        "iam:PassRole",
        "lambda:CreateFunction",
        "lambda:CreateEventSourceMapping",
    },
    "PassRole+CreateLambda+NewDynamo": {
        "iam:PassRole",
        "lambda:CreateFunction",
        "lambda:CreateEventSourceMapping",
        "dynamodb:CreateTable",
        "dynamodb:PutItem",
    },
    "PassRole+GlueEndpoint": {
        "iam:PassRole",
        "glue:CreateDevEndpoint",
        "glue:GetDevEndpoint",
    },
    "PassRole+GlueEndpoints": {
        "iam:PassRole",
        "glue:CreateDevEndpoint",
        "glue:GetDevEndpoints",
    },
    "PassRole+CloudFormation": {
        "cloudformation:CreateStack",
        "cloudformation:DescribeStacks",
    },
    "PassRole+DataPipeline": {
        "datapipeline:CreatePipeline",
        "datapipeline:PutPipelineDefinition",
        "datapipeline:ActivatePipeline",
    },
    "GlueUpdateDevEndpoint": {"glue:UpdateDevEndpoint"},
    "GlueUpdateDevEndpoints": {"glue:UpdateDevEndpoint"},
    "lambda:UpdateFunctionCode": {"lambda:UpdateFunctionCode"},
    "iam:CreateAccessKey": {"iam:CreateAccessKey"},
    "iam:CreateLoginProfile": {"iam:CreateLoginProfile"},
    "iam:UpdateLoginProfile": {"iam:UpdateLoginProfile"},
    "iam:AttachUserPolicy": {"iam:AttachUserPolicy"},
    "iam:AttachGroupPolicy": {"iam:AttachGroupPolicy"},
    "iam:AttachRolePolicy": {"iam:AttachRolePolicy"},
    "AssumeRole+AttachRolePolicy": {"sts:AssumeRole", "iam:AttachRolePolicy"},
    "iam:PutGroupPolicy": {"iam:PutGroupPolicy"},
    "iam:PutRolePolicy": {"iam:PutRolePolicy"},
    "AssumeRole+PutRolePolicy": {"sts:AssumeRole", "iam:PutRolePolicy"},
    "iam:PutUserPolicy": {"iam:PutUserPolicy"},
    "iam:AddUserToGroup": {"iam:AddUserToGroup"},
    "iam:UpdateAssumeRolePolicy": {"iam:UpdateAssumeRolePolicy"},
    "AssumeRole+UpdateAssumeRolePolicy": {
        "sts:AssumeRole",
        "iam:UpdateAssumeRolePolicy",
    },
    # TO-DO: We have to handle AssumeRole just if the resource is * and without conditions
    # "sts:AssumeRole": {"sts:AssumeRole"},
}


class Test_iam_policy_allows_privilege_escalation:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=["us-east-1", "eu-west-1"],
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )

        return audit_info

    # @mock_iam
    # def test_iam_policy_allows_privilege_escalation_sts(self):
    #     iam_client = client("iam", region_name=AWS_REGION)
    #     policy_name = "policy1"
    #     policy_document = {
    #         "Version": "2012-10-17",
    #         "Statement": [
    #             {"Effect": "Allow", "Action": "sts:*", "Resource": "*"},
    #         ],
    #     }
    #     policy_arn = iam_client.create_policy(
    #         PolicyName=policy_name, PolicyDocument=dumps(policy_document)
    #     )["Policy"]["Arn"]

    #     current_audit_info = self.set_mocked_audit_info()
    #     from prowler.providers.aws.services.iam.iam_service import IAM

    #     with mock.patch(
    #         "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
    #         new=current_audit_info,
    #     ), mock.patch(
    #         "prowler.providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation.iam_client",
    #         new=IAM(current_audit_info),
    #     ):
    #         # Test Check
    #         from prowler.providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation import (
    #             iam_policy_allows_privilege_escalation,
    #         )

    #         check = iam_policy_allows_privilege_escalation()
    #         result = check.execute()
    #         assert len(result) == 1
    #         assert result[0].status == "FAIL"
    #         assert (
    #             result[0].status_extended
    #             == f"Custom Policy {policy_arn} allows privilege escalation using the following actions: {{'sts:AssumeRole'}}"
    #         )
    #         assert result[0].resource_id == policy_name
    #         assert result[0].resource_arn == policy_arn

    @mock_iam
    def test_iam_policy_not_allows_privilege_escalation(self):
        iam_client = client("iam", region_name=AWS_REGION)
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "sts:*", "Resource": "*"},
                {"Effect": "Deny", "Action": "sts:*", "Resource": "*"},
                {"Effect": "Deny", "NotAction": "sts:*", "Resource": "*"},
            ],
        }
        policy_arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation import (
                iam_policy_allows_privilege_escalation,
            )

            check = iam_policy_allows_privilege_escalation()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Custom Policy {policy_arn} does not allow privilege escalation"
            )
            assert result[0].resource_id == policy_name
            assert result[0].resource_arn == policy_arn

    @mock_iam
    def test_iam_policy_not_allows_privilege_escalation_glue_GetDevEndpoints(self):
        iam_client = client("iam", region_name=AWS_REGION)
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "lambda:*", "Resource": "*"},
                {"Effect": "Deny", "Action": "lambda:InvokeFunction", "Resource": "*"},
                {
                    "Effect": "Deny",
                    "NotAction": "glue:GetDevEndpoints",
                    "Resource": "*",
                },
            ],
        }
        policy_arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation import (
                iam_policy_allows_privilege_escalation,
            )

            check = iam_policy_allows_privilege_escalation()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Custom Policy {policy_arn} does not allow privilege escalation"
            )
            assert result[0].resource_id == policy_name
            assert result[0].resource_arn == policy_arn

    @mock_iam
    def test_iam_policy_not_allows_privilege_escalation_dynamodb_PutItem(self):
        iam_client = client("iam", region_name=AWS_REGION)
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "lambda:*",
                        "iam:PassRole",
                        "dynamodb:PutItem",
                        "cloudformation:CreateStack",
                        "cloudformation:DescribeStacks",
                        "ec2:RunInstances",
                    ],
                    "Resource": "*",
                },
                {
                    "Effect": "Deny",
                    "Action": ["lambda:InvokeFunction", "cloudformation:CreateStack"],
                    "Resource": "*",
                },
                {"Effect": "Deny", "NotAction": "dynamodb:PutItem", "Resource": "*"},
            ],
        }
        policy_arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation import (
                iam_policy_allows_privilege_escalation,
            )

            check = iam_policy_allows_privilege_escalation()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Custom Policy {policy_arn} does not allow privilege escalation"
            )
            assert result[0].resource_id == policy_name
            assert result[0].resource_arn == policy_arn

    @mock_iam
    def test_iam_policy_allows_privilege_escalation_iam_all_and_ec2_RunInstances(
        self,
    ):
        iam_client = client("iam", region_name=AWS_REGION)
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "iam:*",
                    ],
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Action": ["ec2:RunInstances"],
                    "Resource": "*",
                },
            ],
        }
        policy_arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation import (
                iam_policy_allows_privilege_escalation,
            )

            check = iam_policy_allows_privilege_escalation()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == policy_name
            assert result[0].resource_arn == policy_arn

            assert search(
                f"Custom Policy {policy_arn} allows privilege escalation using the following actions: ",
                result[0].status_extended,
            )
            assert search("iam:PassRole", result[0].status_extended)
            assert search("ec2:RunInstances", result[0].status_extended)

    @mock_iam
    def test_iam_policy_allows_privilege_escalation_iam_PassRole(
        self,
    ):
        iam_client = client("iam", region_name=AWS_REGION)
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/ecs",
                }
            ],
        }
        policy_arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation import (
                iam_policy_allows_privilege_escalation,
            )

            check = iam_policy_allows_privilege_escalation()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == policy_name
            assert result[0].resource_arn == policy_arn

            assert search(
                f"Custom Policy {policy_arn} allows privilege escalation using the following actions: ",
                result[0].status_extended,
            )
            assert search("iam:PassRole", result[0].status_extended)

    @mock_iam
    def test_iam_policy_allows_privilege_escalation_two_combinations(
        self,
    ):
        iam_client = client("iam", region_name=AWS_REGION)
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "iam:PassRole",
                    ],
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Action": ["ec2:RunInstances"],
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "lambda:CreateFunction",
                    ],
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Action": ["lambda:InvokeFunction"],
                    "Resource": "*",
                },
            ],
        }
        policy_arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation import (
                iam_policy_allows_privilege_escalation,
            )

            check = iam_policy_allows_privilege_escalation()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == policy_name
            assert result[0].resource_arn == policy_arn

            assert search(
                f"Custom Policy {policy_arn} allows privilege escalation using the following actions: ",
                result[0].status_extended,
            )
            assert search("iam:PassRole", result[0].status_extended)
            assert search("lambda:InvokeFunction", result[0].status_extended)
            assert search("lambda:CreateFunction", result[0].status_extended)
            assert search("ec2:RunInstances", result[0].status_extended)

    @mock_iam
    def test_iam_policy_allows_privilege_escalation_iam_PassRole_and_other_actions(
        self,
    ):
        iam_client = client("iam", region_name=AWS_REGION)
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/ecs",
                },
                {
                    "Action": "account:GetAccountInformation",
                    "Effect": "Allow",
                    "Resource": "*",
                },
            ],
        }
        policy_arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation import (
                iam_policy_allows_privilege_escalation,
            )

            check = iam_policy_allows_privilege_escalation()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == policy_name
            assert result[0].resource_arn == policy_arn

            assert search(
                f"Custom Policy {policy_arn} allows privilege escalation using the following actions: ",
                result[0].status_extended,
            )
            assert search("iam:PassRole", result[0].status_extended)

    @mock_iam
    def test_iam_policy_allows_privilege_escalation_policies_combination(
        self,
    ):
        current_audit_info = self.set_mocked_audit_info()
        iam_client = client("iam", region_name=AWS_REGION)
        policy_name = "privileged_policy"
        for values in privilege_escalation_policies_combination.values():
            print(list(values))
            # We create a new statement in each loop with the combinations required to allow the privilege escalation
            policy_document = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": list(values),
                        "Resource": "*",
                    },
                ],
            }
            policy_arn = iam_client.create_policy(
                PolicyName=policy_name, PolicyDocument=dumps(policy_document)
            )["Policy"]["Arn"]

            from prowler.providers.aws.services.iam.iam_service import IAM

            with mock.patch(
                "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
                new=current_audit_info,
            ), mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation.iam_client",
                new=IAM(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation import (
                    iam_policy_allows_privilege_escalation,
                )

                check = iam_policy_allows_privilege_escalation()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert result[0].resource_id == policy_name
                assert result[0].resource_arn == policy_arn

                assert search(
                    f"Custom Policy {policy_arn} allows privilege escalation using the following actions: ",
                    result[0].status_extended,
                )

                # Check the actions that allow for privilege escalation
                for action in values:
                    assert search(action, result[0].status_extended)

                # Delete each IAM policy after the test
                iam_client.delete_policy(PolicyArn=policy_arn)

    @mock_iam
    def test_iam_policy_allows_privilege_escalation_two_policies_one_good_one_bad(
        self,
    ):
        current_audit_info = self.set_mocked_audit_info()
        iam_client = client("iam", region_name=AWS_REGION)
        policy_name_1 = "privileged_policy_1"
        policy_document_1 = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["ec2:RunInstances"],
                    "Resource": "*",
                },
            ],
        }
        policy_name_2 = "privileged_policy_2"
        policy_document_2 = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "iam:PassRole",
                    ],
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "lambda:CreateFunction",
                    ],
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Action": ["lambda:InvokeFunction"],
                    "Resource": "*",
                },
            ],
        }
        policy_arn_1 = iam_client.create_policy(
            PolicyName=policy_name_1, PolicyDocument=dumps(policy_document_1)
        )["Policy"]["Arn"]

        policy_arn_2 = iam_client.create_policy(
            PolicyName=policy_name_2, PolicyDocument=dumps(policy_document_2)
        )["Policy"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation import (
                iam_policy_allows_privilege_escalation,
            )

            check = iam_policy_allows_privilege_escalation()
            result = check.execute()
            assert len(result) == 2
            for finding in result:
                if finding.resource_id == policy_name_1:
                    assert finding.status == "PASS"
                    assert finding.resource_arn == policy_arn_1
                    assert (
                        finding.status_extended
                        == f"Custom Policy {policy_arn_1} does not allow privilege escalation"
                    )

                if finding.resource_id == policy_name_2:
                    assert finding.status == "FAIL"
                    assert finding.resource_arn == policy_arn_2

                    assert search(
                        f"Custom Policy {policy_arn_2} allows privilege escalation using the following actions: ",
                        finding.status_extended,
                    )
                    assert search("iam:PassRole", finding.status_extended)
                    assert search("lambda:InvokeFunction", finding.status_extended)
                    assert search("lambda:CreateFunction", finding.status_extended)

    @mock_iam
    def test_iam_policy_allows_privilege_escalation_two_bad_policies(
        self,
    ):
        current_audit_info = self.set_mocked_audit_info()
        iam_client = client("iam", region_name=AWS_REGION)
        policy_name_1 = "privileged_policy_1"
        policy_document_1 = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "iam:PassRole",
                    ],
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Action": ["ec2:RunInstances"],
                    "Resource": "*",
                },
            ],
        }
        policy_name_2 = "privileged_policy_2"
        policy_document_2 = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "iam:PassRole",
                    ],
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "lambda:CreateFunction",
                    ],
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Action": ["lambda:InvokeFunction"],
                    "Resource": "*",
                },
            ],
        }
        policy_arn_1 = iam_client.create_policy(
            PolicyName=policy_name_1, PolicyDocument=dumps(policy_document_1)
        )["Policy"]["Arn"]

        policy_arn_2 = iam_client.create_policy(
            PolicyName=policy_name_2, PolicyDocument=dumps(policy_document_2)
        )["Policy"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation import (
                iam_policy_allows_privilege_escalation,
            )

            check = iam_policy_allows_privilege_escalation()
            result = check.execute()
            assert len(result) == 2
            for finding in result:
                if finding.resource_id == policy_name_1:
                    assert finding.status == "FAIL"
                    assert finding.resource_arn == policy_arn_1

                    assert search(
                        f"Custom Policy {policy_arn_1} allows privilege escalation using the following actions: ",
                        finding.status_extended,
                    )

                    assert search("iam:PassRole", finding.status_extended)
                    assert search("ec2:RunInstances", finding.status_extended)

                if finding.resource_id == policy_name_2:
                    assert finding.status == "FAIL"
                    assert finding.resource_arn == policy_arn_2

                    assert search(
                        f"Custom Policy {policy_arn_2} allows privilege escalation using the following actions: ",
                        finding.status_extended,
                    )
                    assert search("iam:PassRole", finding.status_extended)
                    assert search("lambda:InvokeFunction", finding.status_extended)
                    assert search("lambda:CreateFunction", finding.status_extended)
