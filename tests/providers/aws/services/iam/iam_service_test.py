from json import dumps

from boto3 import client, session
from freezegun import freeze_time
from moto import mock_iam

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.iam.iam_service import IAM, is_service_role

AWS_ACCOUNT_NUMBER = "123456789012"
TEST_DATETIME = "2023-01-01T12:01:01+00:00"


class Test_IAM_Service:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=None,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region="us-east-1",
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
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

    # Test IAM Get Credential Report
    @freeze_time(TEST_DATETIME)
    @mock_iam
    def test__get_credential_report__(self):
        # Generate IAM Client
        iam_client = client("iam")
        # Create IAM User
        username = "user1"
        iam_client.create_user(
            UserName=username,
        )
        # Expected credential report
        expected_credential_report = {
            "user": username,
            "arn": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:user/{username}",
            "user_creation_time": TEST_DATETIME,
            "password_enabled": "false",
            "password_last_used": "not_supported",
            "password_last_changed": TEST_DATETIME,
            "password_next_rotation": "not_supported",
            "mfa_active": "false",
            "access_key_1_active": "false",
            "access_key_1_last_rotated": "N/A",
            "access_key_1_last_used_date": "N/A",
            "access_key_1_last_used_region": "not_supported",
            "access_key_1_last_used_service": "not_supported",
            "access_key_2_active": "false",
            "access_key_2_last_rotated": "N/A",
            "access_key_2_last_used_date": "N/A",
            "access_key_2_last_used_region": "not_supported",
            "access_key_2_last_used_service": "not_supported",
            "cert_1_active": "false",
            "cert_1_last_rotated": "N/A",
            "cert_2_active": "false",
            "cert_2_last_rotated": "N/A",
        }

        # IAM client for this test class
        audit_info = self.set_mocked_audit_info()
        iam = IAM(audit_info)
        assert len(iam.credential_report) == 1
        assert iam.credential_report[0].get("user")
        assert iam.credential_report[0]["user"] == expected_credential_report["user"]

        assert iam.credential_report[0].get("arn")
        assert iam.credential_report[0]["arn"] == expected_credential_report["arn"]

        assert iam.credential_report[0].get("user_creation_time")
        assert (
            iam.credential_report[0]["user_creation_time"]
            == expected_credential_report["user_creation_time"]
        )

        assert iam.credential_report[0].get("password_enabled")
        assert (
            iam.credential_report[0]["password_enabled"]
            == expected_credential_report["password_enabled"]
        )

        assert iam.credential_report[0].get("password_last_used")
        assert (
            iam.credential_report[0]["password_last_used"]
            == expected_credential_report["password_last_used"]
        )

        assert iam.credential_report[0].get("password_last_changed")
        assert (
            iam.credential_report[0]["password_last_changed"]
            == expected_credential_report["password_last_changed"]
        )

        assert iam.credential_report[0].get("password_next_rotation")
        assert (
            iam.credential_report[0]["password_next_rotation"]
            == expected_credential_report["password_next_rotation"]
        )

        assert iam.credential_report[0].get("mfa_active")
        assert (
            iam.credential_report[0]["mfa_active"]
            == expected_credential_report["mfa_active"]
        )

        assert iam.credential_report[0].get("access_key_1_active")
        assert (
            iam.credential_report[0]["access_key_1_active"]
            == expected_credential_report["access_key_1_active"]
        )

        assert iam.credential_report[0].get("access_key_1_last_rotated")
        assert (
            iam.credential_report[0]["access_key_1_last_rotated"]
            == expected_credential_report["access_key_1_last_rotated"]
        )

        assert iam.credential_report[0].get("access_key_1_last_used_date")
        assert (
            iam.credential_report[0]["access_key_1_last_used_date"]
            == expected_credential_report["access_key_1_last_used_date"]
        )

        assert iam.credential_report[0].get("access_key_1_last_used_region")
        assert (
            iam.credential_report[0]["access_key_1_last_used_region"]
            == expected_credential_report["access_key_1_last_used_region"]
        )

        assert iam.credential_report[0].get("access_key_1_last_used_service")
        assert (
            iam.credential_report[0]["access_key_1_last_used_service"]
            == expected_credential_report["access_key_1_last_used_service"]
        )

        assert iam.credential_report[0].get("access_key_2_active")
        assert (
            iam.credential_report[0]["access_key_2_active"]
            == expected_credential_report["access_key_2_active"]
        )

        assert iam.credential_report[0].get("access_key_2_last_rotated")
        assert (
            iam.credential_report[0]["access_key_2_last_rotated"]
            == expected_credential_report["access_key_2_last_rotated"]
        )

        assert iam.credential_report[0].get("access_key_2_last_used_date")
        assert (
            iam.credential_report[0]["access_key_2_last_used_date"]
            == expected_credential_report["access_key_2_last_used_date"]
        )

        assert iam.credential_report[0].get("access_key_2_last_used_region")
        assert (
            iam.credential_report[0]["access_key_2_last_used_region"]
            == expected_credential_report["access_key_2_last_used_region"]
        )

        assert iam.credential_report[0].get("access_key_2_last_used_service")
        assert (
            iam.credential_report[0]["access_key_2_last_used_service"]
            == expected_credential_report["access_key_2_last_used_service"]
        )

        assert iam.credential_report[0].get("cert_1_active")
        assert (
            iam.credential_report[0]["cert_1_active"]
            == expected_credential_report["cert_1_active"]
        )

        assert iam.credential_report[0].get("cert_1_last_rotated")
        assert (
            iam.credential_report[0]["cert_1_last_rotated"]
            == expected_credential_report["cert_1_last_rotated"]
        )

        assert iam.credential_report[0].get("cert_2_active")
        assert (
            iam.credential_report[0]["cert_2_active"]
            == expected_credential_report["cert_2_active"]
        )

        assert iam.credential_report[0].get("cert_2_last_rotated")
        assert (
            iam.credential_report[0]["cert_2_last_rotated"]
            == expected_credential_report["cert_2_last_rotated"]
        )

    # Test IAM Get Roles
    @mock_iam
    def test__get_roles__(self):
        # Generate IAM Client
        iam_client = client("iam")
        # Create 2 IAM Roles
        service_policy_document = {
            "Version": "2008-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        service_role = iam_client.create_role(
            RoleName="test-1",
            AssumeRolePolicyDocument=dumps(service_policy_document),
            Tags=[
                {"Key": "test", "Value": "test"},
            ],
        )["Role"]
        role = iam_client.create_role(
            RoleName="test-2",
            AssumeRolePolicyDocument=dumps(policy_document),
            Tags=[
                {"Key": "test", "Value": "test"},
            ],
        )["Role"]

        # IAM client for this test class
        audit_info = self.set_mocked_audit_info()
        iam = IAM(audit_info)

        assert len(iam.roles) == len(iam_client.list_roles()["Roles"])
        assert iam.roles[0].tags == [
            {"Key": "test", "Value": "test"},
        ]
        assert iam.roles[1].tags == [
            {"Key": "test", "Value": "test"},
        ]
        assert is_service_role(service_role)
        assert not is_service_role(role)

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
            Tags=[
                {"Key": "test", "Value": "test"},
            ],
        )
        iam_client.create_user(
            UserName="user2",
            Tags=[
                {"Key": "test", "Value": "test"},
            ],
        )

        # IAM client for this test class
        audit_info = self.set_mocked_audit_info()
        iam = IAM(audit_info)
        assert len(iam.users) == len(iam_client.list_users()["Users"])
        assert iam.users[0].tags == [
            {"Key": "test", "Value": "test"},
        ]
        assert iam.users[1].tags == [
            {"Key": "test", "Value": "test"},
        ]

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
        assert iam.password_policy.expiration is True
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

    @mock_iam
    def test__get_entities_attached_to_support_roles__no_roles(self):
        iam_client = client("iam")
        _ = iam_client.list_entities_for_policy(
            PolicyArn="arn:aws:iam::aws:policy/aws-service-role/AWSSupportServiceRolePolicy",
            EntityFilter="Role",
        )["PolicyRoles"]

        audit_info = self.set_mocked_audit_info()
        iam = IAM(audit_info)
        assert len(iam.entities_role_attached_to_support_policy) == 0

    @mock_iam
    def test__get_entities_attached_to_support_roles__(self):
        iam_client = client("iam")
        role_name = "test_support"
        assume_role_policy_document = {
            "Version": "2012-10-17",
            "Statement": {
                "Sid": "test",
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole",
            },
        }
        iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(assume_role_policy_document),
        )
        iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/aws-service-role/AWSSupportServiceRolePolicy",
        )

        iam_client.list_entities_for_policy(
            PolicyArn="arn:aws:iam::aws:policy/aws-service-role/AWSSupportServiceRolePolicy",
            EntityFilter="Role",
        )["PolicyRoles"]

        audit_info = self.set_mocked_audit_info()
        iam = IAM(audit_info)
        assert len(iam.entities_role_attached_to_support_policy) == 1
        assert iam.entities_role_attached_to_support_policy[0]["RoleName"] == role_name

    @mock_iam
    def test__get_entities_attached_to_securityaudit_roles__no_roles(self):
        iam_client = client("iam")
        _ = iam_client.list_entities_for_policy(
            PolicyArn="arn:aws:iam::aws:policy/SecurityAudit",
            EntityFilter="Role",
        )["PolicyRoles"]

        audit_info = self.set_mocked_audit_info()
        iam = IAM(audit_info)
        assert len(iam.entities_role_attached_to_securityaudit_policy) == 0

    @mock_iam
    def test__get_entities_attached_to_securityaudit_roles__(self):
        iam_client = client("iam")
        role_name = "test_securityaudit"
        assume_role_policy_document = {
            "Version": "2012-10-17",
            "Statement": {
                "Sid": "test",
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole",
            },
        }
        iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(assume_role_policy_document),
        )
        iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/SecurityAudit",
        )

        iam_client.list_entities_for_policy(
            PolicyArn="arn:aws:iam::aws:policy/SecurityAudit",
            EntityFilter="Role",
        )["PolicyRoles"]

        audit_info = self.set_mocked_audit_info()
        iam = IAM(audit_info)
        assert len(iam.entities_role_attached_to_securityaudit_policy) == 1
        assert (
            iam.entities_role_attached_to_securityaudit_policy[0]["RoleName"]
            == role_name
        )

    @mock_iam
    def test___list_policies__(self):
        iam_client = client("iam")
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "logs:CreateLogGroup", "Resource": "*"},
            ],
        }
        iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )
        audit_info = self.set_mocked_audit_info()
        iam = IAM(audit_info)
        custom_policies = 0
        for policy in iam.policies:
            if policy.type == "Custom":
                custom_policies += 1
                assert policy.name == "policy1"
        assert custom_policies == 1

    @mock_iam
    def test__list_policies_version__(self):
        iam_client = client("iam")
        policy_name = "policy2"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"},
            ],
        }
        iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )
        audit_info = self.set_mocked_audit_info()
        iam = IAM(audit_info)

        custom_policies = 0
        for policy in iam.policies:
            if policy.type == "Custom":
                custom_policies += 1
                assert policy.name == "policy2"
                assert policy.document["Statement"][0]["Effect"] == "Allow"
                assert policy.document["Statement"][0]["Action"] == "*"
                assert policy.document["Statement"][0]["Resource"] == "*"
        assert custom_policies == 1

    # Test IAM List SAML Providers
    @mock_iam
    def test__list_saml_providers__(self):
        iam_client = client("iam")
        xml_template = r"""<EntityDescriptor
    xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="loadbalancer-9.siroe.com">
    <SPSSODescriptor
        AuthnRequestsSigned="false"
        WantAssertionsSigned="false"
        protocolSupportEnumeration=
            "urn:oasis:names:tc:SAML:2.0:protocol">
        <KeyDescriptor use="signing">
            <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                    <X509Certificate>
MIICYDCCAgqgAwIBAgICBoowDQYJKoZIhvcNAQEEBQAwgZIxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
EwpDYWxpZm9ybmlhMRQwEgYDVQQHEwtTYW50YSBDbGFyYTEeMBwGA1UEChMVU3VuIE1pY3Jvc3lz
dGVtcyBJbmMuMRowGAYDVQQLExFJZGVudGl0eSBTZXJ2aWNlczEcMBoGA1UEAxMTQ2VydGlmaWNh
dGUgTWFuYWdlcjAeFw0wNjExMDIxOTExMzRaFw0xMDA3MjkxOTExMzRaMDcxEjAQBgNVBAoTCXNp
cm9lLmNvbTEhMB8GA1UEAxMYbG9hZGJhbGFuY2VyLTkuc2lyb2UuY29tMIGfMA0GCSqGSIb3DQEB
AQUAA4GNADCBiQKBgQCjOwa5qoaUuVnknqf5pdgAJSEoWlvx/jnUYbkSDpXLzraEiy2UhvwpoBgB
EeTSUaPPBvboCItchakPI6Z/aFdH3Wmjuij9XD8r1C+q//7sUO0IGn0ORycddHhoo0aSdnnxGf9V
tREaqKm9dJ7Yn7kQHjo2eryMgYxtr/Z5Il5F+wIDAQABo2AwXjARBglghkgBhvhCAQEEBAMCBkAw
DgYDVR0PAQH/BAQDAgTwMB8GA1UdIwQYMBaAFDugITflTCfsWyNLTXDl7cMDUKuuMBgGA1UdEQQR
MA+BDW1hbGxhQHN1bi5jb20wDQYJKoZIhvcNAQEEBQADQQB/6DOB6sRqCZu2OenM9eQR0gube85e
nTTxU4a7x1naFxzYXK1iQ1vMARKMjDb19QEJIEJKZlDK4uS7yMlf1nFS
                    </X509Certificate>
                </X509Data>
            </KeyInfo>
        </KeyDescriptor>
</EntityDescriptor>"""
        saml_provider_name = "test"
        iam_client.create_saml_provider(
            SAMLMetadataDocument=xml_template, Name=saml_provider_name
        )

        # IAM client for this test class
        audit_info = self.set_mocked_audit_info()
        iam = IAM(audit_info)

        assert len(iam.saml_providers) == 1
        assert iam.saml_providers[0]["Arn"].split("/")[1] == saml_provider_name
