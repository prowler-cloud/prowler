from json import dumps
from unittest import mock

from boto3 import client
from moto import mock_iam


class Test_iam_policy_allows_privilege_escalation:
    @mock_iam
    def test_iam_policy_allows_privilege_escalation_sts(self):
        region = "eu-west-1"
        iam_client = client("iam", region_name=region)
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "sts:*", "Resource": "*"},
            ],
        }
        policy_arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.iam.iam_service import IAM

        current_audit_info.audited_regions = [region]
        with mock.patch(
            "providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation import (
                iam_policy_allows_privilege_escalation,
            )

            check = iam_policy_allows_privilege_escalation()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Customer Managed IAM Policy {policy_arn} allows for privilege escalation using the following actions: {{'sts:*'}}"
            )
            assert result[0].resource_id == policy_name
            assert result[0].resource_arn == policy_arn
            assert result[0].region == region

    @mock_iam
    def test_iam_policy_not_allows_privilege_escalation(self):
        region = "eu-west-1"
        iam_client = client("iam", region_name=region)
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

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.iam.iam_service import IAM

        current_audit_info.audited_regions = [region]
        with mock.patch(
            "providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation import (
                iam_policy_allows_privilege_escalation,
            )

            check = iam_policy_allows_privilege_escalation()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Customer Managed IAM Policy {policy_arn} not allows for privilege escalation"
            )
            assert result[0].resource_id == policy_name
            assert result[0].resource_arn == policy_arn
            assert result[0].region == region

    @mock_iam
    def test_iam_policy_not_allows_privilege_escalation_glue_GetDevEndpoints(self):
        region = "eu-west-1"
        iam_client = client("iam", region_name=region)
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

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.iam.iam_service import IAM

        current_audit_info.audited_regions = [region]
        with mock.patch(
            "providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation import (
                iam_policy_allows_privilege_escalation,
            )

            check = iam_policy_allows_privilege_escalation()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Customer Managed IAM Policy {policy_arn} not allows for privilege escalation"
            )
            assert result[0].resource_id == policy_name
            assert result[0].resource_arn == policy_arn
            assert result[0].region == region

    @mock_iam
    def test_iam_policy_not_allows_privilege_escalation_dynamodb_PutItem(self):
        region = "eu-west-1"
        iam_client = client("iam", region_name=region)
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

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.iam.iam_service import IAM

        current_audit_info.audited_regions = [region]
        with mock.patch(
            "providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.iam.iam_policy_allows_privilege_escalation.iam_policy_allows_privilege_escalation import (
                iam_policy_allows_privilege_escalation,
            )

            check = iam_policy_allows_privilege_escalation()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Customer Managed IAM Policy {policy_arn} allows for privilege escalation using the following actions: {{'dynamodb:PutItem'}}"
            )
            assert result[0].resource_id == policy_name
            assert result[0].resource_arn == policy_arn
            assert result[0].region == region
