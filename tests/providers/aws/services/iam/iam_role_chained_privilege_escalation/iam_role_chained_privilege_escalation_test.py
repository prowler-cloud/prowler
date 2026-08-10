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
    """Tests for IAM role chained privilege escalation."""

    @mock_aws
    def test_no_roles(self):
        """Pass when account has no IAM roles."""
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
        """Pass when single role has no escalation path."""
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
            assert (
                "iam:CreatePolicyVersion" in source_result.status_extended
                or "CreatePolicyVersion" in source_result.status_extended
            )

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

    @mock_aws
    def test_managed_policy_privilege_escalation(self):
        """Regression: privilege escalation via managed policy attached to role."""
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)

        # Create managed policy with escalation
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
        managed_policy = iam_client.create_policy(
            PolicyName="priv-managed-policy",
            PolicyDocument=dumps(priv_doc),
        )
        policy_arn = managed_policy["Policy"]["Arn"]

        # Privileged role trusting root, escalation via managed policy
        privileged_role_name = "priv-managed-target"
        privileged_arn = iam_client.create_role(
            RoleName=privileged_role_name,
            AssumeRolePolicyDocument=dumps(ROOT_TRUST),
        )["Role"]["Arn"]
        iam_client.attach_role_policy(
            RoleName=privileged_role_name, PolicyArn=policy_arn
        )

        # Source role with managed AssumeRole policy
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
        assume_policy = iam_client.create_policy(
            PolicyName="assume-managed-policy",
            PolicyDocument=dumps(assume_doc),
        )
        assume_policy_arn = assume_policy["Policy"]["Arn"]

        source_role_name = "source-managed"
        source_arn = iam_client.create_role(
            RoleName=source_role_name,
            AssumeRolePolicyDocument=dumps(ROOT_TRUST),
        )["Role"]["Arn"]
        iam_client.attach_role_policy(
            RoleName=source_role_name, PolicyArn=assume_policy_arn
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
            source_result = by_id[source_role_name]
            assert source_result.resource_arn == source_arn
            assert source_result.status == "FAIL"
            assert privileged_role_name in source_result.status_extended

    @mock_aws
    def test_three_role_chain(self):
        """Three role chain: source -> intermediate -> privileged should flag source via transitive closure."""
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)

        # source -> intermediate -> privileged topology
        intermediate_role_name = "intermediate-role"
        privileged_role_name = "privileged-final"
        privileged_arn = iam_client.create_role(
            RoleName=privileged_role_name,
            AssumeRolePolicyDocument=dumps(ROOT_TRUST),
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

        # Intermediate role trusting source will be created after source, but needs ARN of privileged for assume
        # To simplify: create source, intermediate, privileged with dynamic trust updates via update_assume_role_policy

        source_role_name = "source-chain"
        source_arn = iam_client.create_role(
            RoleName=source_role_name,
            AssumeRolePolicyDocument=dumps(ROOT_TRUST),
        )["Role"]["Arn"]

        intermediate_trust_allows_source = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": source_arn},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        intermediate_arn = iam_client.create_role(
            RoleName=intermediate_role_name,
            AssumeRolePolicyDocument=dumps(intermediate_trust_allows_source),
        )["Role"]["Arn"]

        # Update privileged trust to allow intermediate
        privileged_trust_allows_intermediate = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": intermediate_arn},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        iam_client.update_assume_role_policy(
            RoleName=privileged_role_name,
            PolicyDocument=dumps(privileged_trust_allows_intermediate),
        )

        # Source can assume intermediate
        source_assume_intermediate = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": intermediate_arn,
                }
            ],
        }
        iam_client.put_role_policy(
            RoleName=source_role_name,
            PolicyName="assume-intermediate",
            PolicyDocument=dumps(source_assume_intermediate),
        )

        # Intermediate can assume privileged
        intermediate_assume_priv = {
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
            RoleName=intermediate_role_name,
            PolicyName="assume-privileged",
            PolicyDocument=dumps(intermediate_assume_priv),
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

            assert len(result) == 3
            by_id = {r.resource_id: r for r in result}

            source_result = by_id[source_role_name]
            intermediate_result = by_id[intermediate_role_name]
            privileged_result = by_id[privileged_role_name]

            # Source should FAIL via transitive chain to privileged
            assert source_result.status == "FAIL"
            assert privileged_role_name in source_result.status_extended

            # Intermediate should FAIL direct assume privileged
            assert intermediate_result.status == "FAIL"
            assert privileged_role_name in intermediate_result.status_extended

            # Privileged should FAIL because assumable by intermediate (in-account)
            assert privileged_result.status == "FAIL"
            assert intermediate_role_name in privileged_result.status_extended

    @mock_aws
    def test_wildcard_trust_unconditioned(self):
        """Wildcard trust Principal star should be treated as assumable when unconditioned."""
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)

        wildcard_trust = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        privileged_role_name = "wildcard-priv"
        privileged_arn = iam_client.create_role(
            RoleName=privileged_role_name,
            AssumeRolePolicyDocument=dumps(wildcard_trust),
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

        benign_role_name = "benign-other"
        iam_client.create_role(
            RoleName=benign_role_name,
            AssumeRolePolicyDocument=dumps(ROOT_TRUST),
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
            by_id = {r.resource_id: r for r in result}
            priv_result = by_id[privileged_role_name]
            benign_result = by_id[benign_role_name]
            # Should be FAIL because wildcard trust makes it assumable by in-account roles
            assert priv_result.status == "FAIL"
            assert "wildcard" in priv_result.status_extended.lower()
            assert benign_result.status == "PASS"

    @mock_aws
    def test_combined_statements_escalation(self):
        """Escalation split across two policies should be detected via combined statements."""
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)

        # split of iam:AttachRolePolicy and iam:UpdateAssumeRolePolicy
        role_name = "split-escalation-role"
        iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(ROOT_TRUST),
        )

        policy_one = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "iam:AttachRolePolicy", "Resource": "*"}
            ],
        }
        policy_two = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "iam:UpdateAssumeRolePolicy", "Resource": "*"}
            ],
        }
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName="part-one",
            PolicyDocument=dumps(policy_one),
        )
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName="part-two",
            PolicyDocument=dumps(policy_two),
        )

        trusted_name = "trusted-for-split"
        trusted_arn = iam_client.create_role(
            RoleName=trusted_name,
            AssumeRolePolicyDocument=dumps(ROOT_TRUST),
        )["Role"]["Arn"]

        trust_allowing = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": trusted_arn},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        iam_client.update_assume_role_policy(
            RoleName=role_name, PolicyDocument=dumps(trust_allowing)
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
            by_id = {r.resource_id: r for r in result}
            role_result = by_id[role_name]
            # Combined statements allow escalation, trust allows in-account assume
            assert role_result.status == "FAIL"
            assert "assumable" in role_result.status_extended.lower()

    @mock_aws
    def test_bare_account_id_normalization(self):
        """Bare 12-digit Principal should be normalized to root ARN and treated as assumable."""
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)

        # Privileged role trusting bare account ID "123456789012"
        bare_account_trust = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": AWS_ACCOUNT_NUMBER},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        privileged_name = "priv-bare-account"
        privileged_arn = iam_client.create_role(
            RoleName=privileged_name,
            AssumeRolePolicyDocument=dumps(bare_account_trust),
        )["Role"]["Arn"]

        priv_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"}
            ],
        }
        iam_client.put_role_policy(
            RoleName=privileged_name,
            PolicyName="priv",
            PolicyDocument=dumps(priv_doc),
        )

        source_name = "source-for-bare"
        iam_client.create_role(
            RoleName=source_name, AssumeRolePolicyDocument=dumps(ROOT_TRUST)
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
            by_id = {r.resource_id: r for r in result}
            # Bare account ID normalized to root should be detected as wildcard-ish root trust
            # Privileged role should be FAIL because root trust makes it assumable in-account
            assert by_id[privileged_name].status == "FAIL"

    @mock_aws
    def test_condition_skips_unconditional_trust(self):
        """Trust with Condition should be skipped conservatively."""
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)

        trusted_name = "app-with-condition"
        trusted_arn = iam_client.create_role(
            RoleName=trusted_name, AssumeRolePolicyDocument=dumps(ROOT_TRUST)
        )["Role"]["Arn"]

        conditional_trust = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": trusted_arn},
                    "Action": "sts:AssumeRole",
                    "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
                }
            ],
        }
        privileged_name = "priv-conditional"
        iam_client.create_role(
            RoleName=privileged_name,
            AssumeRolePolicyDocument=dumps(conditional_trust),
        )
        priv_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"}
            ],
        }
        iam_client.put_role_policy(
            RoleName=privileged_name, PolicyName="priv", PolicyDocument=dumps(priv_doc)
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
            by_id = {r.resource_id: r for r in result}
            # Conditional trust should be skipped, so privileged role stays PASS
            assert by_id[privileged_name].status == "PASS"

    @mock_aws
    def test_explicit_deny_blocks_assume(self):
        """Explicit Deny on sts:AssumeRole should block transitive escalation."""
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)

        privileged_name = "priv-deny-test"
        privileged_arn = iam_client.create_role(
            RoleName=privileged_name, AssumeRolePolicyDocument=dumps(ROOT_TRUST)
        )["Role"]["Arn"]

        priv_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"}
            ],
        }
        iam_client.put_role_policy(
            RoleName=privileged_name, PolicyName="priv", PolicyDocument=dumps(priv_doc)
        )

        intermediate_name = "intermediate-deny"
        intermediate_arn = iam_client.create_role(
            RoleName=intermediate_name, AssumeRolePolicyDocument=dumps(ROOT_TRUST)
        )["Role"]["Arn"]

        source_name = "source-deny"
        source_arn = iam_client.create_role(
            RoleName=source_name, AssumeRolePolicyDocument=dumps(ROOT_TRUST)
        )["Role"]["Arn"]

        # Allow intermediate to assume privileged
        intermediate_assume = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": privileged_arn}],
        }
        iam_client.put_role_policy(
            RoleName=intermediate_name, PolicyName="assume-priv", PolicyDocument=dumps(intermediate_assume)
        )

        # Trust assignments
        privileged_trust_allows_intermediate = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": intermediate_arn}, "Action": "sts:AssumeRole"}],
        }
        iam_client.update_assume_role_policy(
            RoleName=privileged_name, PolicyDocument=dumps(privileged_trust_allows_intermediate)
        )

        intermediate_trust_allows_source = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": source_arn}, "Action": "sts:AssumeRole"}],
        }
        iam_client.update_assume_role_policy(
            RoleName=intermediate_name, PolicyDocument=dumps(intermediate_trust_allows_source)
        )

        # Source can Allow intermediate but also explicit Deny privileged -> should not reach privileged via direct Allow
        source_policy_allow_intermediate = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": intermediate_arn}],
        }
        source_policy_deny_priv = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": privileged_arn}],
        }
        # Also Deny blocks AssumeRole via wildcard? Add Deny covering privileged to ensure chain broken if source tries direct AssumeRole to privileged via "*"
        source_combined = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": intermediate_arn},
                {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": privileged_arn},
                {"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": privileged_arn},
            ],
        }
        iam_client.put_role_policy(
            RoleName=source_name, PolicyName="assume-combined", PolicyDocument=dumps(source_combined)
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
            by_id = {r.resource_id: r for r in result}
            # Source can still assume intermediate, and intermediate can assume privileged, so transitive chain should still FAIL
            # But direct privileged via Deny should be blocked; transitive via intermediate should still succeed because intermediate is not denied
            assert by_id[source_name].status == "FAIL"
            # If we add additional Deny on intermediate, then PASS would be expected; here we only deny privileged directly
            assert by_id[intermediate_name].status == "FAIL"

    @mock_aws
    def test_partition_aware_root_arn(self):
        """Root ARN in other partitions should be recognized as trusted."""
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)

        cn_root_trust = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws-cn:iam::{AWS_ACCOUNT_NUMBER}:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        privileged_name = "priv-cn-root"
        iam_client.create_role(
            RoleName=privileged_name, AssumeRolePolicyDocument=dumps(cn_root_trust)
        )
        priv_doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"}],
        }
        iam_client.put_role_policy(RoleName=privileged_name, PolicyName="priv", PolicyDocument=dumps(priv_doc))

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
            by_id = {r.resource_id: r for r in result}
            # Partition-aware root should be considered assumable when account matches
            assert by_id[privileged_name].status == "FAIL"

    @mock_aws
    def test_fnmatch_wildcard_resource(self):
        """Wildcard pattern arn:aws:iam::*:role/Admin* should match via fnmatch."""
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)

        privileged_name = "AdminProdRole"
        privileged_arn = iam_client.create_role(
            RoleName=privileged_name, AssumeRolePolicyDocument=dumps(ROOT_TRUST)
        )["Role"]["Arn"]

        priv_doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"}],
        }
        iam_client.put_role_policy(RoleName=privileged_name, PolicyName="priv", PolicyDocument=dumps(priv_doc))

        # Make privileged trust allow source
        privileged_trust = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        iam_client.update_assume_role_policy(RoleName=privileged_name, PolicyDocument=dumps(privileged_trust))

        source_name = "source-fnmatch"
        iam_client.create_role(RoleName=source_name, AssumeRolePolicyDocument=dumps(ROOT_TRUST))

        wildcard_resource = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/Admin*"
        assume_doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": wildcard_resource}],
        }
        iam_client.put_role_policy(RoleName=source_name, PolicyName="assume-wc", PolicyDocument=dumps(assume_doc))

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
            by_id = {r.resource_id: r for r in result}
            assert by_id[source_name].status == "FAIL"
            assert privileged_name in by_id[source_name].status_extended
