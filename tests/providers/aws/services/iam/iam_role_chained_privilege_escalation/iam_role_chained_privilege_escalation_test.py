from json import dumps
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

# Common trust allowing root – safe for simple roles
ROOT_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"},
            "Action": "sts:AssumeRole",
        }
    ],
}


class Test_iam_role_chained_privilege_escalation:
    @mock_aws
    def test_no_roles(self):
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.iam.iam_role_chained_privilege_escalation.iam_role_chained_privilege_escalation.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.iam.iam_role_chained_privilege_escalation.iam_role_chained_privilege_escalation import (
                iam_role_chained_privilege_escalation,
            )

            check = iam_role_chained_privilege_escalation()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_single_role_no_escalation(self):
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)

        role_name = "safe-role"
        role_arn = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(ROOT_TRUST),
        )["Role"]["Arn"]

        # Benign policy – no privilege escalation
        policy_name = "read-only"
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": "*"}
            ],
        }
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=dumps(policy_doc),
        )

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.iam.iam_role_chained_privilege_escalation.iam_role_chained_privilege_escalation.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.iam.iam_role_chained_privilege_escalation.iam_role_chained_privilege_escalation import (
                iam_role_chained_privilege_escalation,
            )

            check = iam_role_chained_privilege_escalation()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_id == role_name
            assert result[0].resource_arn == role_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].status == "PASS"
            assert (
                "does not allow chained privilege escalation"
                in result[0].status_extended.lower()
            )

    @mock_aws
    def test_role_can_assume_privileged_role(self):
        """Source role can assume privileged role (privileged has iam:CreatePolicyVersion) -> source FAIL."""
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)

        # Privileged role – has privilege escalation action
        privileged_role_name = "privileged-target"
        privileged_arn = iam_client.create_role(
            RoleName=privileged_role_name,
            AssumeRolePolicyDocument=dumps(ROOT_TRUST),
        )["Role"]["Arn"]

        priv_policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
                    "Resource": "*",
                }
            ],
        }
        iam_client.put_role_policy(
            RoleName=privileged_role_name,
            PolicyName="priv-escalation",
            PolicyDocument=dumps(priv_policy_doc),
        )

        # Source role – can AssumeRole into privileged role
        source_role_name = "low-priv-source"
        source_arn = iam_client.create_role(
            RoleName=source_role_name,
            AssumeRolePolicyDocument=dumps(ROOT_TRUST),
        )["Role"]["Arn"]

        assume_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": privileged_arn,
                }
            ],
        }
        iam_client.put_role_policy(
            RoleName=source_role_name,
            PolicyName="assume-privileged",
            PolicyDocument=dumps(assume_doc),
        )

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.iam.iam_role_chained_privilege_escalation.iam_role_chained_privilege_escalation.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.iam.iam_role_chained_privilege_escalation.iam_role_chained_privilege_escalation import (
                iam_role_chained_privilege_escalation,
            )

            check = iam_role_chained_privilege_escalation()
            result = check.execute()

            # Two roles in account – at least source must FAIL
            assert len(result) == 2
            result_by_id = {r.resource_id: r for r in result}

            assert source_role_name in result_by_id
            assert privileged_role_name in result_by_id

            source_result = result_by_id[source_role_name]
            assert source_result.resource_arn == source_arn
            assert source_result.status == "FAIL"
            # Must name the privileged target role and the escalation actions
            assert privileged_role_name in source_result.status_extended
            assert "iam:CreatePolicyVersion" in source_result.status_extended or "CreatePolicyVersion" in source_result.status_extended

            # Privileged role itself: benign trust (root), not assumable by any role ARN -> should PASS in this setup
            privileged_result = result_by_id[privileged_role_name]
            # It is privileged but not assumable by in-account role ARN, so it stays PASS per second branch
            # The check only marks privileged role FAIL if trust Principal includes in-account role ARN
            assert privileged_result.status == "PASS"

    @mock_aws
    def test_privileged_role_assumable_by_in_account_role(self):
        """Privileged role is assumable by another role in account – privileged role FAIL via trust chain."""
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)

        # Low-priv role that will be trusted
        trusted_role_name = "app-role"
        trusted_arn = iam_client.create_role(
            RoleName=trusted_role_name,
            AssumeRolePolicyDocument=dumps(ROOT_TRUST),
        )["Role"]["Arn"]

        # Privileged role trusting app-role
        trust_allowing_app_role = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": trusted_arn},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        privileged_role_name = "admin-via-broken-trust"
        privileged_arn = iam_client.create_role(
            RoleName=privileged_role_name,
            AssumeRolePolicyDocument=dumps(trust_allowing_app_role),
        )["Role"]["Arn"]

        priv_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:CreatePolicyVersion",
                    "Resource": "*",
                }
            ],
        }
        iam_client.put_role_policy(
            RoleName=privileged_role_name,
            PolicyName="priv",
            PolicyDocument=dumps(priv_doc),
        )

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.iam.iam_role_chained_privilege_escalation.iam_role_chained_privilege_escalation.iam_client",
                new=IAM(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.iam.iam_role_chained_privilege_escalation.iam_role_chained_privilege_escalation import (
                iam_role_chained_privilege_escalation,
            )

            check = iam_role_chained_privilege_escalation()
            result = check.execute()

            assert len(result) == 2
            by_id = {r.resource_id: r for r in result}

            privileged_result = by_id[privileged_role_name]
            trusted_result = by_id[trusted_role_name]

            # Privileged role should be FAIL because it is assumable by in-account role
            assert privileged_result.resource_arn == privileged_arn
            assert privileged_result.status == "FAIL"
            assert "assumable" in privileged_result.status_extended.lower()
            assert trusted_role_name in privileged_result.status_extended

            # App role has no escalation itself and does not assume privileged via policy – should PASS
            assert trusted_result.resource_arn == trusted_arn
            assert trusted_result.status == "PASS"
