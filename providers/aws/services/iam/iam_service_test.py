import json

from boto3 import client, session
from moto import mock_iam

from providers.aws.lib.audit_info.models import AWS_Audit_Info, session
from providers.aws.services.iam.iam_service import IAM

AWS_ACCOUNT_NUMBER = 123456789012


class Test_IAM_Service:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=None,
            audited_user_id=None,
            audited_partition=None,
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
        )
        return audit_info

    # Test IAM Client
    @mock_iam
    def test__get_client__(self):
        # IAM client for this test class
        audit_info = self.set_mocked_audit_info()
        iam = IAM(audit_info)
        assert iam.client.__class__.__name__ == "IAM"

    # Test IAM Session
    @mock_iam
    def test__get_session__(self):
        # IAM client for this test class
        audit_info = self.set_mocked_audit_info()
        iam = IAM(audit_info)
        assert iam.session.__class__.__name__ == "Session"

    # Test IAM Client
    @mock_iam
    def test__get_credential_report__(self):
        # Generate IAM Client
        iam_client = client("iam")
        # Create an IAM Users
        iam_client.create_user(
            UserName="user1",
        )

        # IAM client for this test class
        audit_info = self.set_mocked_audit_info()
        iam = IAM(audit_info)
        assert len(iam.credential_report) == len(iam_client.list_users()["Users"])

    # Test IAM Get Roles
    @mock_iam
    def test__get_roles__(self):
        # Generate IAM Client
        iam_client = client("iam")
        # Create 2 IAM Roles
        iam_client.create_role(
            RoleName="role1",
            AssumeRolePolicyDocument="string",
        )
        iam_client.create_role(
            RoleName="role2",
            AssumeRolePolicyDocument="string",
        )

        # IAM client for this test class
        audit_info = self.set_mocked_audit_info()
        iam = IAM(audit_info)

        assert len(iam.roles) == len(iam_client.list_roles()["Roles"])

    # Test IAM Get Groups
    @mock_iam
    def test__get_groups__(self):
        # Generate IAM Client
        iam_client = client("iam")
        # Create 2 IAM Groups
        iam_client.create_group(
            GroupName="group1",
        )
        iam_client.create_group(
            GroupName="group2",
        )

        # IAM client for this test class
        audit_info = self.set_mocked_audit_info()
        iam = IAM(audit_info)
        assert len(iam.groups) == len(iam_client.list_groups()["Groups"])

    # Test IAM Get Users
    @mock_iam
    def test__get_users__(self):
        # Generate IAM Client
        iam_client = client("iam")
        # Create 2 IAM Users
        iam_client.create_user(
            UserName="user1",
        )
        iam_client.create_user(
            UserName="user2",
        )

        # IAM client for this test class
        audit_info = self.set_mocked_audit_info()
        iam = IAM(audit_info)
        assert len(iam.users) == len(iam_client.list_users()["Users"])

    # Test IAM Get Customer Managed Policies
    @mock_iam
    def test__get_customer_managed_policies__(self):
        # Generate IAM Client
        iam_client = client("iam")
        # Create a new IAM Policy
        policy_document = """
{
  "Version": "2012-10-17",
  "Statement":
    {
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::example_bucket"
    }
}
"""
        iam_client.create_policy(
            PolicyName="policy1",
            PolicyDocument=policy_document,
        )
        # IAM client for this test class
        audit_info = self.set_mocked_audit_info()
        iam = IAM(audit_info)
        assert len(iam.customer_managed_policies) == len(
            iam_client.list_policies(Scope="Local")["Policies"]
        )

    # Test IAM Get Customer Managed Policies Version
    @mock_iam
    def test__get_customer_managed_policies_version__(self):
        # Generate IAM Client
        iam_client = client("iam")
        # Create a new IAM Policy
        policy_document = """
{
  "Version": "2012-10-17",
  "Statement":
    {
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::example_bucket"
    }
}
"""
        iam_client.create_policy(
            PolicyName="policy1",
            PolicyDocument=policy_document,
        )

        # IAM client for this test class
        audit_info = self.set_mocked_audit_info()
        print()
        iam = IAM(audit_info)

        assert len(iam.customer_managed_policies) == 1
        assert iam.customer_managed_policies[0]["PolicyDocument"] == json.loads(
            policy_document
        )

    # Test IAM Get Account Summary
    @mock_iam
    def test__get_account_summary__(self):
        # Generate IAM Client
        iam_client = client("iam")
        account_summary = iam_client.get_account_summary()

        # IAM client for this test class
        audit_info = self.set_mocked_audit_info()
        iam = IAM(audit_info)

        assert iam.account_summary == account_summary

    # Test IAM Get Password Policy
    @mock_iam
    def test__get_password_policy__(self):
        # Generate IAM Client
        iam_client = client("iam")
        # Update Password Policy
        min_password_length = 123
        require_symbols = False
        require_numbers = True
        require_upper = True
        require_lower = False
        allow_users_to_change = True
        max_password_age = 123
        password_reuse_prevention = 24
        hard_expiry = True

        iam_client.update_account_password_policy(
            MinimumPasswordLength=min_password_length,
            RequireSymbols=require_symbols,
            RequireNumbers=require_numbers,
            RequireUppercaseCharacters=require_upper,
            RequireLowercaseCharacters=require_lower,
            AllowUsersToChangePassword=allow_users_to_change,
            MaxPasswordAge=max_password_age,
            PasswordReusePrevention=password_reuse_prevention,
            HardExpiry=hard_expiry,
        )

        # IAM client for this test class
        audit_info = self.set_mocked_audit_info()
        iam = IAM(audit_info)

        assert iam.password_policy.length == min_password_length
        assert iam.password_policy.symbols == require_symbols
        assert iam.password_policy.numbers == require_numbers
        assert iam.password_policy.uppercase == require_upper
        assert iam.password_policy.lowercase == require_lower
        assert iam.password_policy.allow_change == allow_users_to_change
        assert iam.password_policy.expiration == True
        assert iam.password_policy.max_age == max_password_age
        assert iam.password_policy.reuse_prevention == password_reuse_prevention
        assert iam.password_policy.hard_expiry == hard_expiry

    # Test IAM List MFA Device
    @mock_iam
    def test__list_mfa_devices__(self):
        # Generate IAM Client
        iam_client = client("iam")
        # Generate IAM user
        iam_client.create_user(
            UserName="user1",
        )
        # Create virtual MFA device
        mfa_device_name = "test-mfa-device"
        virtual_mfa_device = iam_client.create_virtual_mfa_device(
            VirtualMFADeviceName=mfa_device_name,
        )
        iam_client.enable_mfa_device(
            UserName="user1",
            SerialNumber=virtual_mfa_device["VirtualMFADevice"]["SerialNumber"],
            AuthenticationCode1="123456",
            AuthenticationCode2="123456",
        )

        # IAM client for this test class
        audit_info = self.set_mocked_audit_info()
        iam = IAM(audit_info)

        assert len(iam.users) == 1
        assert len(iam.users[0].mfa_devices) == 1
        assert (
            iam.users[0].mfa_devices[0].serial_number
            == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:mfa/{mfa_device_name}"
        )
        assert iam.users[0].mfa_devices[0].type == "mfa"

    # Test IAM List Virtual MFA Device
    @mock_iam
    def test__list_virtual_mfa_devices__(self):
        # Generate IAM Client
        iam_client = client("iam")
        # Generate IAM user
        username = "user1"
        iam_client.create_user(
            UserName=username,
        )
        # Create virtual MFA device
        mfa_device_name = "test-mfa-device"
        virtual_mfa_device = iam_client.create_virtual_mfa_device(
            VirtualMFADeviceName=mfa_device_name,
        )
        iam_client.enable_mfa_device(
            UserName=username,
            SerialNumber=virtual_mfa_device["VirtualMFADevice"]["SerialNumber"],
            AuthenticationCode1="123456",
            AuthenticationCode2="123456",
        )

        # IAM client for this test class
        audit_info = self.set_mocked_audit_info()
        iam = IAM(audit_info)

        assert len(iam.virtual_mfa_devices) == 1
        assert (
            iam.virtual_mfa_devices[0]["SerialNumber"]
            == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:mfa/{mfa_device_name}"
        )
        assert iam.virtual_mfa_devices[0]["User"]["UserName"] == username

    # Test IAM Get Group Users
    @mock_iam
    def test__get_group_users__(self):
        # Generate IAM Client
        iam_client = client("iam")
        # Generate IAM user
        username = "user1"
        iam_client.create_user(
            UserName=username,
        )
        # Generate IAM group
        group = "test-group"
        iam_client.create_group(GroupName=group)
        # Add user to group
        iam_client.add_user_to_group(GroupName=group, UserName=username)

        # IAM client for this test class
        audit_info = self.set_mocked_audit_info()
        iam = IAM(audit_info)

        assert len(iam.groups) == 1
        assert iam.groups[0].name == group
        assert iam.groups[0].arn == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:group/{group}"
        assert len(iam.groups[0].users) == 1
        assert iam.groups[0].users[0].name == username

    # Test IAM List Attached Group Policies
    @mock_iam
    def test__list_attached_group_policies__(self):
        # Generate IAM Client
        iam_client = client("iam")
        # Generate IAM user
        username = "user1"
        iam_client.create_user(
            UserName=username,
        )
        # Generate IAM group
        group = "test-group"
        iam_client.create_group(GroupName=group)

        # Create a new IAM Policy
        policy_document = """
{
  "Version": "2012-10-17",
  "Statement":
    {
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::example_bucket"
    }
}
"""
        policy_name = "policy1"
        policy = iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=policy_document,
        )

        # Attach group policy
        iam_client.attach_group_policy(
            GroupName=group, PolicyArn=policy["Policy"]["Arn"]
        )

        # IAM client for this test class
        audit_info = self.set_mocked_audit_info()
        iam = IAM(audit_info)

        assert len(iam.groups) == 1
        assert iam.groups[0].name == group
        assert len(iam.groups[0].attached_policies) == 1
        assert iam.groups[0].attached_policies[0]["PolicyName"] == policy_name
        assert (
            iam.groups[0].attached_policies[0]["PolicyArn"] == policy["Policy"]["Arn"]
        )
