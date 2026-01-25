from unittest import mock
import sys
from prowler.providers.aws.services.iam.iam_service import Policy

class Test_iam_policy_allows_passrole_without_condition:
    def test_iam_policy_allows_passrole_no_condition(self):
        # 1. Create the Mock Client
        iam_client_mock = mock.MagicMock()
        iam_client_mock.region = "us-east-1"
        iam_client_mock.audited_account = "123456789012"
        
        # 2. Create the "Toxic" Policy Object
        toxic_policy = mock.MagicMock()
        toxic_policy.name = "ToxicPolicy"
        toxic_policy.arn = "arn:aws:iam::123456789012:policy/ToxicPolicy"
        toxic_policy.type = "Custom"
        toxic_policy.document = {
            "Statement": [
                {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}
            ]
        }
        iam_client_mock.policies = {toxic_policy.arn: toxic_policy}

        # 3. Create a fake module to hold our mock client
        module_mock = mock.MagicMock()
        module_mock.iam_client = iam_client_mock

        # 4. SURGICAL BYPASS: Patch sys.modules to inject our fake module
        # This prevents the REAL iam_client.py from ever loading/crashing
        with mock.patch.dict(sys.modules, {"prowler.providers.aws.services.iam.iam_client": module_mock}):
            # Import the check ONLY inside this safe context
            from prowler.providers.aws.services.iam.iam_policy_allows_passrole_without_condition.iam_policy_allows_passrole_without_condition import (
                iam_policy_allows_passrole_without_condition,
            )
            
            check = iam_policy_allows_passrole_without_condition()
            result = check.execute()

            # 5. Verify Fail
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "ToxicPolicy"

    def test_iam_policy_allows_passrole_with_condition(self):
        # 1. Mock Client
        iam_client_mock = mock.MagicMock()
        iam_client_mock.region = "us-east-1"
        
        # 2. Safe Policy Object
        safe_policy = mock.MagicMock()
        safe_policy.name = "SafePolicy"
        safe_policy.arn = "arn:aws:iam::123456789012:policy/SafePolicy"
        safe_policy.type = "Custom"
        safe_policy.document = {
            "Statement": [{
                "Effect": "Allow", 
                "Action": "iam:PassRole", 
                "Resource": "*",
                "Condition": {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}
            }]
        }
        iam_client_mock.policies = {safe_policy.arn: safe_policy}

        # 3. Module Mock
        module_mock = mock.MagicMock()
        module_mock.iam_client = iam_client_mock

        # 4. Bypass & Run
        with mock.patch.dict(sys.modules, {"prowler.providers.aws.services.iam.iam_client": module_mock}):
            from prowler.providers.aws.services.iam.iam_policy_allows_passrole_without_condition.iam_policy_allows_passrole_without_condition import (
                iam_policy_allows_passrole_without_condition,
            )
            
            check = iam_policy_allows_passrole_without_condition()
            result = check.execute()

            # 5. Verify Pass
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "SafePolicy"
