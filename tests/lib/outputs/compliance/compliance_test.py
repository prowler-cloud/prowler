from mock import MagicMock

from prowler.lib.check.compliance_models import (
    CIS_Requirement_Attribute,
    Compliance_Base_Model,
    Compliance_Requirement,
)
from prowler.lib.outputs.compliance.compliance import (
    get_check_compliance_frameworks_in_input,
)

CIS_1_4_AWS_NAME = "cis_1.4_aws"
CIS_1_4_AWS = Compliance_Base_Model(
    Framework="CIS",
    Provider="AWS",
    Version="1.4",
    Description="The CIS Benchmark for CIS Amazon Web Services Foundations Benchmark, v1.4.0, Level 1 and 2 provides prescriptive guidance for configuring security options for a subset of Amazon Web Services. It has an emphasis on foundational, testable, and architecture agnostic settings",
    Requirements=[
        Compliance_Requirement(
            Checks=[],
            Id="2.1.3",
            Description="Ensure MFA Delete is enabled on S3 buckets",
            Attributes=[
                CIS_Requirement_Attribute(
                    Section="2.1. Simple Storage Service (S3)",
                    Profile="Level 1",
                    AssessmentStatus="Automated",
                    Description="Once MFA Delete is enabled on your sensitive and classified S3 bucket it requires the user to have two forms of authentication.",
                    RationaleStatement="Adding MFA delete to an S3 bucket, requires additional authentication when you change the version state of your bucket or you delete and object version adding another layer of security in the event your security credentials are compromised or unauthorized access is granted.",
                    ImpactStatement="",
                    RemediationProcedure="Perform the steps below to enable MFA delete on an S3 bucket.\n\nNote:\n-You cannot enable MFA Delete using the AWS Management Console. You must use the AWS CLI or API.\n-You must use your 'root' account to enable MFA Delete on S3 buckets.\n\n**From Command line:**\n\n1. Run the s3api put-bucket-versioning command\n\n```\naws s3api put-bucket-versioning --profile my-root-profile --bucket Bucket_Name --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa “arn:aws:iam::aws_account_id:mfa/root-account-mfa-device passcode”\n```",
                    AuditProcedure='Perform the steps below to confirm MFA delete is configured on an S3 Bucket\n\n**From Console:**\n\n1. Login to the S3 console at `https://console.aws.amazon.com/s3/`\n\n2. Click the `Check` box next to the Bucket name you want to confirm\n\n3. In the window under `Properties`\n\n4. Confirm that Versioning is `Enabled`\n\n5. Confirm that MFA Delete is `Enabled`\n\n**From Command Line:**\n\n1. Run the `get-bucket-versioning`\n```\naws s3api get-bucket-versioning --bucket my-bucket\n```\n\nOutput example:\n```\n<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"> \n <Status>Enabled</Status>\n <MfaDelete>Enabled</MfaDelete> \n</VersioningConfiguration>\n```\n\nIf the Console or the CLI output does not show Versioning and MFA Delete `enabled` refer to the remediation below.',
                    AdditionalInformation="",
                    References="https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html#MultiFactorAuthenticationDelete:https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingMFADelete.html:https://aws.amazon.com/blogs/security/securing-access-to-aws-using-mfa-part-3/:https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_lost-or-broken.html",
                )
            ],
        )
    ],
)
CIS_1_5_AWS_NAME = "cis_1.5_aws"
CIS_1_5_AWS = Compliance_Base_Model(
    Framework="CIS",
    Provider="AWS",
    Version="1.5",
    Description="The CIS Amazon Web Services Foundations Benchmark provides prescriptive guidance for configuring security options for a subset of Amazon Web Services with an emphasis on foundational, testable, and architecture agnostic settings.",
    Requirements=[
        Compliance_Requirement(
            Checks=[],
            Id="2.1.3",
            Description="Ensure MFA Delete is enabled on S3 buckets",
            Attributes=[
                CIS_Requirement_Attribute(
                    Section="2.1. Simple Storage Service (S3)",
                    Profile="Level 1",
                    AssessmentStatus="Automated",
                    Description="Once MFA Delete is enabled on your sensitive and classified S3 bucket it requires the user to have two forms of authentication.",
                    RationaleStatement="Adding MFA delete to an S3 bucket, requires additional authentication when you change the version state of your bucket or you delete and object version adding another layer of security in the event your security credentials are compromised or unauthorized access is granted.",
                    ImpactStatement="",
                    RemediationProcedure="Perform the steps below to enable MFA delete on an S3 bucket.\n\nNote:\n-You cannot enable MFA Delete using the AWS Management Console. You must use the AWS CLI or API.\n-You must use your 'root' account to enable MFA Delete on S3 buckets.\n\n**From Command line:**\n\n1. Run the s3api put-bucket-versioning command\n\n```\naws s3api put-bucket-versioning --profile my-root-profile --bucket Bucket_Name --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa “arn:aws:iam::aws_account_id:mfa/root-account-mfa-device passcode”\n```",
                    AuditProcedure='Perform the steps below to confirm MFA delete is configured on an S3 Bucket\n\n**From Console:**\n\n1. Login to the S3 console at `https://console.aws.amazon.com/s3/`\n\n2. Click the `Check` box next to the Bucket name you want to confirm\n\n3. In the window under `Properties`\n\n4. Confirm that Versioning is `Enabled`\n\n5. Confirm that MFA Delete is `Enabled`\n\n**From Command Line:**\n\n1. Run the `get-bucket-versioning`\n```\naws s3api get-bucket-versioning --bucket my-bucket\n```\n\nOutput example:\n```\n<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"> \n <Status>Enabled</Status>\n <MfaDelete>Enabled</MfaDelete> \n</VersioningConfiguration>\n```\n\nIf the Console or the CLI output does not show Versioning and MFA Delete `enabled` refer to the remediation below.',
                    AdditionalInformation="",
                    References="https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html#MultiFactorAuthenticationDelete:https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingMFADelete.html:https://aws.amazon.com/blogs/security/securing-access-to-aws-using-mfa-part-3/:https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_lost-or-broken.html",
                )
            ],
        )
    ],
)

NOT_PRESENT_COMPLIANCE_NAME = "not_present_compliance_name"
NOT_PRESENT_COMPLIANCE = Compliance_Base_Model(
    Framework="NOT_EXISTENT",
    Provider="NOT_EXISTENT",
    Version="NOT_EXISTENT",
    Description="NOT_EXISTENT",
    Requirements=[],
)


class TestCompliance:
    def test_get_check_compliance_frameworks_all_none(self):
        check_id = None
        bulk_checks_metadata = None
        input_compliance_frameworks = None
        assert (
            get_check_compliance_frameworks_in_input(
                check_id, bulk_checks_metadata, input_compliance_frameworks
            )
            == []
        )

    def test_get_check_compliance_frameworks_all(self):
        check_id = "test-check"
        bulk_check_metadata = [CIS_1_4_AWS, CIS_1_5_AWS]
        bulk_checks_metadata = {}
        bulk_checks_metadata[check_id] = MagicMock()
        bulk_checks_metadata[check_id].Compliance = bulk_check_metadata
        input_compliance_frameworks = [CIS_1_4_AWS_NAME, CIS_1_5_AWS_NAME]
        assert get_check_compliance_frameworks_in_input(
            check_id, bulk_checks_metadata, input_compliance_frameworks
        ) == [CIS_1_4_AWS, CIS_1_5_AWS]

    def test_get_check_compliance_frameworks_two_of_three(self):
        check_id = "test-check"
        bulk_check_metadata = [CIS_1_4_AWS, CIS_1_5_AWS, NOT_PRESENT_COMPLIANCE]
        bulk_checks_metadata = {}
        bulk_checks_metadata[check_id] = MagicMock()
        bulk_checks_metadata[check_id].Compliance = bulk_check_metadata
        input_compliance_frameworks = [CIS_1_4_AWS_NAME, CIS_1_5_AWS_NAME]
        assert get_check_compliance_frameworks_in_input(
            check_id, bulk_checks_metadata, input_compliance_frameworks
        ) == [CIS_1_4_AWS, CIS_1_5_AWS]
