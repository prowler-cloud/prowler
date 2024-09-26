from prowler.providers.aws.services.iam.lib.privilege_escalation import (
    check_privilege_escalation,
    find_privilege_escalation_combinations,
)


class Test_PrivilegeEscalation:
    def test_find_privilege_escalation_combinations_no_priv_escalation(self):
        allowed_actions = set()
        denied_actions = set()
        allowed_not_actions = set()
        denied_not_actions = set()

        allowed_actions.add("s3:GetObject")
        denied_actions.add("s3:PutObject")
        denied_not_actions.add("s3:DeleteObject")

        assert (
            find_privilege_escalation_combinations(
                allowed_actions, denied_actions, allowed_not_actions, denied_not_actions
            )
            == set()
        )

    def test_find_privilege_escalation_combinations_priv_escalation_iam_all_and_ec2_RunInstances(
        self,
    ):
        allowed_actions = set()
        denied_actions = set()
        allowed_not_actions = set()
        denied_not_actions = set()

        allowed_actions.add("iam:*")
        denied_actions.add("ec2:RunInstances")

        assert find_privilege_escalation_combinations(
            allowed_actions, denied_actions, allowed_not_actions, denied_not_actions
        ) == {
            "iam:Put*",
            "iam:AddUserToGroup",
            "iam:AttachRolePolicy",
            "iam:PassRole",
            "iam:CreateLoginProfile",
            "iam:CreateAccessKey",
            "iam:AttachGroupPolicy",
            "iam:SetDefaultPolicyVersion",
            "iam:PutRolePolicy",
            "iam:UpdateAssumeRolePolicy",
            "iam:*",
            "iam:PutGroupPolicy",
            "iam:PutUserPolicy",
            "iam:CreatePolicyVersion",
            "iam:AttachUserPolicy",
            "iam:UpdateLoginProfile",
        }

    def test_find_privilege_escalation_combinations_priv_escalation_iam_PassRole(self):
        allowed_actions = set()
        allowed_not_actions = set()
        denied_actions = set()
        denied_not_actions = set()

        allowed_actions.add("iam:PassRole")

        assert find_privilege_escalation_combinations(
            allowed_actions, denied_actions, allowed_not_actions, denied_not_actions
        ) == {"iam:PassRole"}

    def test_check_privilege_escalation_no_priv_escalation(self):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": ["arn:aws:s3:::example_bucket/*"],
                }
            ]
        }

        assert check_privilege_escalation(policy) == ""

    def test_check_privilege_escalation_priv_escalation_iam_all_and_ec2_RunInstances(
        self,
    ):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["iam:*"],
                    "Resource": ["*"],
                },
                {
                    "Effect": "Deny",
                    "Action": ["ec2:RunInstances"],
                    "Resource": ["*"],
                },
            ]
        }

        result = check_privilege_escalation(policy)

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
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["iam:PassRole"],
                    "Resource": ["*"],
                }
            ]
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
                    "NotAction": "iam:Put*",
                    "Resource": "*",
                }
            ],
        }

        result = check_privilege_escalation(policy)
        assert "iam:Put*" not in result
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

    def test_check_privilege_escalation_priv_escalation_with_invalid_not_action(
        self,
    ):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Statement1",
                    "Effect": "Allow",
                    "NotAction": "prowler:action",
                    "Resource": "*",
                }
            ],
        }

        result = check_privilege_escalation(policy)
        assert "proler:action" not in result
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
