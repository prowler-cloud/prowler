from prowler.providers.aws.services.iam.lib.privilege_escalation import (
    check_privilege_escalation,
    privilege_escalation_policies_combination,
)


# Helper function to parse the output string into a set for easier comparison
def parse_result_string(result_str: str) -> set:
    """Helper to parse the output string back into a set."""
    if not result_str:
        return set()
    # Removes the single quotes around each action and splits by comma+space
    return set(part.strip("'") for part in result_str.split(", "))


class Test_PrivilegeEscalation:
    def test_check_privilege_escalation_no_priv_escalation(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": ["arn:aws:s3:::example_bucket/*"],
                }
            ],
        }
        expected_result = ""
        assert check_privilege_escalation(policy) == expected_result

    def test_check_privilege_escalation_priv_escalation_iam_all_and_ec2_RunInstances(
        self,
    ):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["iam:*"],
                    "Resource": ["*"],
                },
                {
                    "Effect": "Deny",
                    "Action": ["ec2:RunInstances"],  # This denies one part of a combo
                    "Resource": ["*"],
                },
            ],
        }
        # Should match all IAM combos, but NOT PassRole+EC2
        result = check_privilege_escalation(policy)
        assert "ec2:RunInstances" not in result
        assert "iam:Put*" in result
        assert "iam:AddUserToGroup" in result
        assert "iam:AttachRolePolicy" in result
        assert "iam:PassRole" in result
        assert "iam:CreateLoginProfile" in result
        assert "iam:CreateAccessKey" in result
        assert "iam:AttachGroupPolicy" in result
        assert "iam:SetDefaultPolicyVersion" in result
        assert "iam:PutRolePolicy" in result
        assert "iam:UpdateAssumeRolePolicy" in result
        assert "iam:*" in result
        assert "iam:PutGroupPolicy" in result
        assert "iam:PutUserPolicy" in result
        assert "iam:CreatePolicyVersion" in result
        assert "iam:AttachUserPolicy" in result
        assert "iam:UpdateLoginProfile" in result

    def test_check_privilege_escalation_priv_escalation_iam_PassRole(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["iam:PassRole"],
                    "Resource": ["*"],
                }
            ],
        }
        result = check_privilege_escalation(policy)
        assert "iam:PassRole" in result

    def test_check_privilege_escalation_priv_escalation_iam_PassRole_using_wildcard(
        self,
    ):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["iam:*Role"],  # Should expand to include PassRole
                    "Resource": ["*"],
                }
            ],
        }
        result = check_privilege_escalation(policy)
        assert "iam:PassRole" in result

    def test_check_privilege_escalation_priv_escalation_not_action(
        self,
    ):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Statement1",
                    "Effect": "Allow",
                    "NotAction": "iam:Put*",  # Allows everything EXCEPT iam:Put* actions
                    "Resource": "*",
                }
            ],
        }
        # Should match all combos EXCEPT those requiring iam:Put*
        result = check_privilege_escalation(policy)
        assert "iam:*" not in result
        assert "iam:Put*" not in result
        assert "'iam:PutGroupPolicy'" not in result
        assert "iam:AddUserToGroup" in result
        assert "iam:AttachRolePolicy" in result
        assert "iam:PassRole" in result
        assert "iam:CreateLoginProfile" in result
        assert "iam:CreateAccessKey" in result
        assert "iam:AttachGroupPolicy" in result
        assert "iam:SetDefaultPolicyVersion" in result
        assert "iam:UpdateAssumeRolePolicy" in result
        assert "iam:CreatePolicyVersion" in result
        assert "iam:AttachUserPolicy" in result
        assert "iam:UpdateLoginProfile" in result

    def test_check_privilege_escalation_priv_escalation_with_invalid_not_action(
        self,
    ):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Statement1",
                    "Effect": "Allow",
                    "NotAction": "prowler:action",  # Invalid action -> Allows ALL
                    "Resource": "*",
                }
            ],
        }
        # Since it allows ALL, expect all original patterns from ALL combos
        result = check_privilege_escalation(policy)
        for combo_patterns in privilege_escalation_policies_combination.values():
            for pattern in combo_patterns:
                assert (
                    f"'{pattern}'" in result
                ), f"Expected pattern '{pattern}' not found in result: {result}"

    def test_check_privilege_escalation_administrator_policy(self):
        policy_document_admin = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Statement01",
                    "Effect": "Allow",
                    "Action": ["*"],  # Admin policy
                    "Resource": "*",
                }
            ],
        }
        # Admin policy should match ALL combos, so expect all original patterns
        result = check_privilege_escalation(policy_document_admin)
        for combo_patterns in privilege_escalation_policies_combination.values():
            for pattern in combo_patterns:
                assert (
                    f"'{pattern}'" in result
                ), f"Expected pattern '{pattern}' not found in result: {result}"
