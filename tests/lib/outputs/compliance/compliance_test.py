from os import path
from unittest import mock

from prowler.lib.check.compliance_models import (
    CIS_Requirement_Attribute,
    Compliance,
    Compliance_Requirement,
)
from prowler.lib.check.models import Check_Report, load_check_metadata
from prowler.lib.outputs.compliance.compliance import get_check_compliance


class TestCompliance:
    def test_get_check_compliance_aws(self):
        check_compliance = [
            Compliance(
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
            ),
            Compliance(
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
            ),
        ]

        finding = Check_Report(
            load_check_metadata(
                f"{path.dirname(path.realpath(__file__))}/../fixtures/metadata.json"
            ).json()
        )
        finding.resource_details = "Test resource details"
        finding.resource_id = "test-resource"
        finding.resource_arn = "test-arn"
        finding.region = "eu-west-1"
        finding.status = "PASS"
        finding.status_extended = "This is a test"

        bulk_checks_metadata = {}
        bulk_checks_metadata["iam_user_accesskey_unused"] = mock.MagicMock()
        bulk_checks_metadata["iam_user_accesskey_unused"].Compliance = check_compliance

        assert get_check_compliance(finding, "aws", bulk_checks_metadata) == {
            "CIS-1.4": ["2.1.3"],
            "CIS-1.5": ["2.1.3"],
        }

    def test_get_check_compliance_gcp(self):
        check_compliance = [
            Compliance(
                Framework="CIS",
                Provider="GCP",
                Version="2.0",
                Description="This CIS Benchmark is the product of a community consensus process and consists of secure configuration guidelines developed for Google Cloud Computing Platform",
                Requirements=[
                    Compliance_Requirement(
                        Checks=[],
                        Id="2.1.3",
                        Description="Ensure compute instances do not use the default service account with full access to all Cloud APIs",
                        Attributes=[
                            CIS_Requirement_Attribute(
                                Section="2.1. Compute Engine",
                                Profile="Level 1",
                                AssessmentStatus="Automated",
                                Description="The default service account should not be used for compute instances as it has full access to all Cloud APIs.",
                                RationaleStatement="The default service account has full access to all Cloud APIs and should not be used for compute instances.",
                                ImpactStatement="",
                                RemediationProcedure="Perform the following to ensure compute instances do not use the default service account with full access to all Cloud APIs:\n\n1. Navigate to the 'Compute Engine' section of the Google Cloud Console at `https://console.cloud.google.com/compute/instances`\n2. Click on the instance to be modified\n3. Click the 'Edit' button\n4. In the 'Service account' section, select a service account that has the least privilege necessary for the instance\n5. Click 'Save' to apply the changes",
                                AuditProcedure="Perform the following to ensure compute instances do not use the default service account with full access to all Cloud APIs:\n\n1. Navigate to the section of the Google Cloud Console at `https://console.cloud.google.com/compute/instances`\n2. Click on the instance to be audited\n3. In the section, verify that the service account selected has the least privilege necessary for the instance",
                                AdditionalInformation="",
                                References="https://cloud.google.com/compute/docs/access/service-accounts#default_service_account",
                            )
                        ],
                    )
                ],
            ),
            Compliance(
                Framework="CIS",
                Provider="GCP",
                Version="2.1",
                Description="This CIS Benchmark is the product of a community consensus process and consists of secure configuration guidelines developed for Google Cloud Computing Platform",
                Requirements=[
                    Compliance_Requirement(
                        Checks=[],
                        Id="2.1.3",
                        Description="Ensure compute instances do not use the default service account with full access to all Cloud APIs",
                        Attributes=[
                            CIS_Requirement_Attribute(
                                Section="2.1. Compute Engine",
                                Profile="Level 1",
                                AssessmentStatus="Automated",
                                Description="The default service account should not be used for compute instances as it has full access to all Cloud APIs.",
                                RationaleStatement="The default service account has full access to all Cloud APIs and should not be used for compute instances.",
                                ImpactStatement="",
                                RemediationProcedure="Perform the following to ensure compute instances do not use the default service account with full access to all Cloud APIs:\n\n1. Navigate to the 'Compute Engine' section of the Google Cloud Console at `https://console.cloud.google.com/compute/instances`\n2. Click on the instance to be modified\n3. Click the 'Edit' button\n4. In the 'Service account' section, select a service account that has the least privilege necessary for the instance\n5. Click 'Save' to apply the changes",
                                AuditProcedure="Perform the following to ensure compute instances do not use the default service account with full access to all Cloud APIs:\n\n1. Navigate to the section of the Google Cloud Console at `https://console.cloud.google.com/compute/instances`\n2. Click on the instance to be audited\n3. In the section, verify that the service account selected has the least privilege necessary for the instance",
                                AdditionalInformation="",
                                References="https://cloud.google.com/compute/docs/access/service-accounts#default_service_account",
                            )
                        ],
                    )
                ],
            ),
        ]

        finding = Check_Report(
            load_check_metadata(
                f"{path.dirname(path.realpath(__file__))}/../fixtures/metadata.json"
            ).json()
        )
        finding.resource_details = "Test resource details"
        finding.resource_id = "test-resource"
        finding.resource_arn = "test-arn"
        finding.region = "eu-west-1"
        finding.status = "PASS"
        finding.status_extended = "This is a test"

        bulk_checks_metadata = {}
        bulk_checks_metadata["iam_user_accesskey_unused"] = mock.MagicMock()
        bulk_checks_metadata["iam_user_accesskey_unused"].Compliance = check_compliance

        assert get_check_compliance(finding, "gcp", bulk_checks_metadata) == {
            "CIS-2.0": ["2.1.3"],
            "CIS-2.1": ["2.1.3"],
        }

    def test_get_check_compliance_azure(self):
        check_compliance = [
            Compliance(
                Framework="CIS",
                Provider="Azure",
                Version="2.0",
                Description="This CIS Benchmark is the product of a community consensus process and consists of secure configuration guidelines developed for Azuee Platform",
                Requirements=[
                    Compliance_Requirement(
                        Checks=[],
                        Id="2.1.3",
                        Description="Ensure compute instances do not use the default service account with full access to all Cloud APIs",
                        Attributes=[
                            CIS_Requirement_Attribute(
                                Section="2.1. Compute Engine",
                                Profile="Level 1",
                                AssessmentStatus="Automated",
                                Description="The default service account should not be used for compute instances as it has full access to all Cloud APIs.",
                                RationaleStatement="The default service account has full access to all Cloud APIs and should not be used for compute instances.",
                                ImpactStatement="",
                                RemediationProcedure="Perform the following to ensure compute instances do not use the default service account with full access to all Cloud APIs:\n\n1. Navigate to the 'Compute Engine' section of the Google Cloud Console at `https://console.cloud.google.com/compute/instances`\n2. Click on the instance to be modified\n3. Click the 'Edit' button\n4. In the 'Service account' section, select a service account that has the least privilege necessary for the instance\n5. Click 'Save' to apply the changes",
                                AuditProcedure="Perform the following to ensure compute instances do not use the default service account with full access to all Cloud APIs:\n\n1. Navigate to the section of the Google Cloud Console at `https://console.cloud.google.com/compute/instances`\n2. Click on the instance to be audited\n3. In the section, verify that the service account selected has the least privilege necessary for the instance",
                                AdditionalInformation="",
                                References="https://cloud.google.com/compute/docs/access/service-accounts#default_service_account",
                            )
                        ],
                    )
                ],
            ),
            Compliance(
                Framework="CIS",
                Provider="Azure",
                Version="2.1",
                Description="This CIS Benchmark is the product of a community consensus process and consists of secure configuration guidelines developed for Azure Platform",
                Requirements=[
                    Compliance_Requirement(
                        Checks=[],
                        Id="2.1.3",
                        Description="Ensure compute instances do not use the default service account with full access to all Cloud APIs",
                        Attributes=[
                            CIS_Requirement_Attribute(
                                Section="2.1. Compute Engine",
                                Profile="Level 1",
                                AssessmentStatus="Automated",
                                Description="The default service account should not be used for compute instances as it has full access to all Cloud APIs.",
                                RationaleStatement="The default service account has full access to all Cloud APIs and should not be used for compute instances.",
                                ImpactStatement="",
                                RemediationProcedure="Perform the following to ensure compute instances do not use the default service account with full access to all Cloud APIs:\n\n1. Navigate to the 'Compute Engine' section of the Google Cloud Console at `https://console.cloud.google.com/compute/instances`\n2. Click on the instance to be modified\n3. Click the 'Edit' button\n4. In the 'Service account' section, select a service account that has the least privilege necessary for the instance\n5. Click 'Save' to apply the changes",
                                AuditProcedure="Perform the following to ensure compute instances do not use the default service account with full access to all Cloud APIs:\n\n1. Navigate to the section of the Google Cloud Console at `https://console.cloud.google.com/compute/instances`\n2. Click on the instance to be audited\n3. In the section, verify that the service account selected has the least privilege necessary for the instance",
                                AdditionalInformation="",
                                References="https://cloud.google.com/compute/docs/access/service-accounts#default_service_account",
                            )
                        ],
                    )
                ],
            ),
        ]

        finding = Check_Report(
            load_check_metadata(
                f"{path.dirname(path.realpath(__file__))}/../fixtures/metadata.json"
            ).json()
        )
        finding.resource_details = "Test resource details"
        finding.resource_id = "test-resource"
        finding.resource_arn = "test-arn"
        finding.region = "eu-west-1"
        finding.status = "PASS"
        finding.status_extended = "This is a test"

        bulk_checks_metadata = {}
        bulk_checks_metadata["iam_user_accesskey_unused"] = mock.MagicMock()
        bulk_checks_metadata["iam_user_accesskey_unused"].Compliance = check_compliance

        assert get_check_compliance(finding, "azure", bulk_checks_metadata) == {
            "CIS-2.0": ["2.1.3"],
            "CIS-2.1": ["2.1.3"],
        }

    def test_get_check_compliance_kubernetes(self):
        check_compliance = [
            Compliance(
                Framework="CIS",
                Provider="Kubernetes",
                Version="2.0",
                Description="This CIS Benchmark is the product of a community consensus process and consists of secure configuration guidelines developed for Kubernetes Platform",
                Requirements=[
                    Compliance_Requirement(
                        Checks=[],
                        Id="2.1.3",
                        Description="Ensure compute instances do not use the default service account with full access to all Cloud APIs",
                        Attributes=[
                            CIS_Requirement_Attribute(
                                Section="2.1. Compute Engine",
                                Profile="Level 1",
                                AssessmentStatus="Automated",
                                Description="The default service account should not be used for compute instances as it has full access to all Cloud APIs.",
                                RationaleStatement="The default service account has full access to all Cloud APIs and should not be used for compute instances.",
                                ImpactStatement="",
                                RemediationProcedure="Perform the following to ensure compute instances do not use the default service account with full access to all Cloud APIs:\n\n1. Navigate to the 'Compute Engine' section of the Google Cloud Console at `https://console.cloud.google.com/compute/instances`\n2. Click on the instance to be modified\n3. Click the 'Edit' button\n4. In the 'Service account' section, select a service account that has the least privilege necessary for the instance\n5. Click 'Save' to apply the changes",
                                AuditProcedure="Perform the following to ensure compute instances do not use the default service account with full access to all Cloud APIs:\n\n1. Navigate to the section of the Google Cloud Console at `https://console.cloud.google.com/compute/instances`\n2. Click on the instance to be audited\n3. In the section, verify that the service account selected has the least privilege necessary for the instance",
                                AdditionalInformation="",
                                References="https://cloud.google.com/compute/docs/access/service-accounts#default_service_account",
                            )
                        ],
                    )
                ],
            ),
            Compliance(
                Framework="CIS",
                Provider="Kubernetes",
                Version="2.1",
                Description="This CIS Benchmark is the product of a community consensus process and consists of secure configuration guidelines developed for Kubernetes Platform",
                Requirements=[
                    Compliance_Requirement(
                        Checks=[],
                        Id="2.1.3",
                        Description="Ensure compute instances do not use the default service account with full access to all Cloud APIs",
                        Attributes=[
                            CIS_Requirement_Attribute(
                                Section="2.1. Compute Engine",
                                Profile="Level 1",
                                AssessmentStatus="Automated",
                                Description="The default service account should not be used for compute instances as it has full access to all Cloud APIs.",
                                RationaleStatement="The default service account has full access to all Cloud APIs and should not be used for compute instances.",
                                ImpactStatement="",
                                RemediationProcedure="Perform the following to ensure compute instances do not use the default service account with full access to all Cloud APIs:\n\n1. Navigate to the 'Compute Engine' section of the Google Cloud Console at `https://console.cloud.google.com/compute/instances`\n2. Click on the instance to be modified\n3. Click the 'Edit' button\n4. In the 'Service account' section, select a service account that has the least privilege necessary for the instance\n5. Click 'Save' to apply the changes",
                                AuditProcedure="Perform the following to ensure compute instances do not use the default service account with full access to all Cloud APIs:\n\n1. Navigate to the section of the Google Cloud Console at `https://console.cloud.google.com/compute/instances`\n2. Click on the instance to be audited\n3. In the section, verify that the service account selected has the least privilege necessary for the instance",
                                AdditionalInformation="",
                                References="https://cloud.google.com/compute/docs/access/service-accounts#default_service_account",
                            )
                        ],
                    )
                ],
            ),
        ]

        finding = Check_Report(
            load_check_metadata(
                f"{path.dirname(path.realpath(__file__))}/../fixtures/metadata.json"
            ).json()
        )
        print(finding)
        finding.resource_details = "Test resource details"
        finding.resource_id = "test-resource"
        finding.resource_arn = "test-arn"
        finding.region = "eu-west-1"
        finding.status = "PASS"
        finding.status_extended = "This is a test"

        bulk_checks_metadata = {}
        bulk_checks_metadata["iam_user_accesskey_unused"] = mock.MagicMock()
        bulk_checks_metadata["iam_user_accesskey_unused"].Compliance = check_compliance

        assert get_check_compliance(finding, "kubernetes", bulk_checks_metadata) == {
            "CIS-2.0": ["2.1.3"],
            "CIS-2.1": ["2.1.3"],
        }
