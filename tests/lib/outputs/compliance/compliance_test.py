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
                Name="CIS Amazon Web Services Foundations Benchmark v1.4.0",
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
                Name="CIS Amazon Web Services Foundations Benchmark v1.5.0",
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
            metadata=load_check_metadata(
                f"{path.dirname(path.realpath(__file__))}/../fixtures/metadata.json"
            ).json(),
            resource={},
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
                Name="CIS Google Cloud Platform Foundation Benchmark v2.0.0",
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
                Name="CIS Google Cloud Platform Foundation Benchmark v2.1.0",
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
            metadata=load_check_metadata(
                f"{path.dirname(path.realpath(__file__))}/../fixtures/metadata.json"
            ).json(),
            resource={},
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
                Name="CIS Microsoft Azure Foundations Benchmark v2.0.0",
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
                Name="CIS Microsoft Azure Foundations Benchmark v2.1.0",
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
            metadata=load_check_metadata(
                f"{path.dirname(path.realpath(__file__))}/../fixtures/metadata.json"
            ).json(),
            resource={},
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
                Name="CIS Kubernetes Benchmark v2.0.0",
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
                Name="CIS Kubernetes Benchmark v2.1.0",
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
            metadata=load_check_metadata(
                f"{path.dirname(path.realpath(__file__))}/../fixtures/metadata.json"
            ).json(),
            resource={},
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

        assert get_check_compliance(finding, "kubernetes", bulk_checks_metadata) == {
            "CIS-2.0": ["2.1.3"],
            "CIS-2.1": ["2.1.3"],
        }

    def test_get_check_compliance_github(self):
        check_compliance = [
            Compliance(
                Framework="CIS",
                Name="CIS GitHub Benchmark v1.0.0",
                Provider="Github",
                Version="1.0",
                Description="This document provides prescriptive guidance for establishing a secure configuration posture for securing GitHub.",
                Requirements=[
                    Compliance_Requirement(
                        Checks=[],
                        Id="1.1.11",
                        Description="Ensure all open comments are resolved before allowing code change merging",
                        Attributes=[
                            CIS_Requirement_Attribute(
                                Section="1.1",
                                Profile="Level 2",
                                AssessmentStatus="Manual",
                                Description='Organizations should enforce a "no open comments" policy before allowing code change merging.',
                                RationaleStatement="In an open code change proposal, reviewers can leave comments containing their questions and suggestions. These comments can also include potential bugs and security issues. Requiring all comments on a code change proposal to be resolved before it can be merged ensures that every concern is properly addressed or acknowledged before the new code changes are introduced to the code base.",
                                ImpactStatement="Code change proposals containing open comments would not be able to be merged into the code base.",
                                RemediationProcedure='For each code repository in use, require open comments to be resolved before the relevant code change can be merged by performing the following:\n \n\n 1. On GitHub.com, navigate to the main page of the repository.\n 2. Under your repository name, click **Settings**.\n 3. In the "Code and automation" section of the sidebar, click **Branches**.\n 4. Next to "Branch protection rules", verify that there is at least one rule for your main branch. If there is, click **Edit** to its right. If there isn\'t, click **Add rule**.\n 5. If you add the rule, under "Branch name pattern", type the branch name or pattern you want to protect.\n 6. Select **Require conversation resolution before merging**.\n 7. Click **Create** or **Save changes**.',
                                AuditProcedure='For every code repository in use, verify that each merged code change does not contain open, unattended comments by performing the following:\n \n\n 1. On GitHub.com, navigate to the main page of the repository.\n 2. Under your repository name, click **Settings**.\n 3. In the "Code and automation" section of the sidebar, click **Branches**.\n 4. Next to "Branch protection rules", verify that there is at least one rule for your main branch. If there is, click **Edit** to its right. If there isn\'t, you are not compliant.\n 5. Ensure that **Require conversation resolution before merging** is checked.',
                                AdditionalInformation="",
                                References="",
                            )
                        ],
                    )
                ],
            )
        ]

        finding = Check_Report(
            metadata=load_check_metadata(
                f"{path.dirname(path.realpath(__file__))}/../fixtures/metadata.json"
            ).json(),
            resource={},
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

        assert get_check_compliance(finding, "github", bulk_checks_metadata) == {
            "CIS-1.0": ["1.1.11"],
        }


class TestComplianceOutput:
    """Test ComplianceOutput file extension parsing fix."""

    def test_compliance_output_file_extension_with_dots(self):
        """Test that ComplianceOutput correctly parses file extensions when framework names contain dots."""
        from prowler.lib.outputs.compliance.generic.generic import GenericCompliance

        compliance = Compliance(
            Framework="CIS",
            Version="5.0",
            Provider="AWS",
            Name="CIS Amazon Web Services Foundations Benchmark v5.0",
            Description="Test compliance framework",
            Requirements=[],
        )

        # Test with problematic file path that contains dots in framework name
        # This simulates the real scenario from Prowler App S3 integration
        problematic_file_path = "output/compliance/prowler-output-123456789012-20250101120000_cis_5.0_aws.csv"

        # Create GenericCompliance object with file_path (no explicit file_extension)
        compliance_output = GenericCompliance(
            findings=[], compliance=compliance, file_path=problematic_file_path
        )

        assert compliance_output.file_extension == ".csv"
        assert compliance_output.file_extension != ".0_aws.csv"

    def test_compliance_output_file_extension_explicit(self):
        """Test that ComplianceOutput uses explicit file_extension when provided."""
        from prowler.lib.outputs.compliance.generic.generic import GenericCompliance

        compliance = Compliance(
            Framework="CIS",
            Version="5.0",
            Provider="AWS",
            Name="CIS Amazon Web Services Foundations Benchmark v5.0",
            Description="Test compliance framework",
            Requirements=[],
        )

        compliance_output = GenericCompliance(
            findings=[],
            compliance=compliance,
            file_path="output/compliance/test",
            file_extension=".csv",
        )

        assert compliance_output.file_extension == ".csv"


class TestComplianceCheckHelperModule:
    """Tests for the new ``compliance_check`` leaf module that hosts
    ``get_check_compliance``.

    This module exists to break the cyclic import chain
    ``finding -> compliance.compliance -> universal.* -> finding`` that
    CodeQL flagged. It must be:
      - importable directly without pulling in the universal pipeline
      - re-exported by ``compliance.compliance`` for backward compatibility
      - the SAME function object, regardless of import path
    """

    def test_module_is_importable_directly(self):
        """The helper module must be importable on its own — it is the
        leaf used by ``finding.py`` to break the cyclic import chain."""
        from prowler.lib.outputs.compliance import compliance_check

        assert hasattr(compliance_check, "get_check_compliance")
        assert callable(compliance_check.get_check_compliance)

    def test_helper_module_only_depends_on_check_models_and_logger(self):
        """The helper must not pull in universal pipeline modules; that
        was the whole point of extracting it. Inspecting the module's
        own imports keeps it honest without polluting ``sys.modules``."""
        import inspect

        from prowler.lib.outputs.compliance import compliance_check

        source = inspect.getsource(compliance_check)
        # Only these two prowler imports are allowed in the leaf module
        assert "from prowler.lib.check.models import Check_Report" in source
        assert "from prowler.lib.logger import logger" in source
        # And NOT these (would re-introduce the cycle):
        assert "from prowler.lib.outputs.compliance.universal" not in source
        assert "from prowler.lib.outputs.finding" not in source
        assert "from prowler.lib.outputs.ocsf" not in source

    def test_re_export_from_compliance_compliance(self):
        """``compliance.compliance.get_check_compliance`` must point to
        the same function as ``compliance.compliance_check.get_check_compliance``."""
        from prowler.lib.outputs.compliance.compliance import (
            get_check_compliance as via_compliance,
        )
        from prowler.lib.outputs.compliance.compliance_check import (
            get_check_compliance as via_helper,
        )

        assert via_compliance is via_helper

    def test_re_export_from_finding_module(self):
        """``finding.get_check_compliance`` must point to the same
        function. Test mocks rely on this attribute existing on the
        ``prowler.lib.outputs.finding`` module."""
        from prowler.lib.outputs.compliance.compliance_check import (
            get_check_compliance as via_helper,
        )
        from prowler.lib.outputs.finding import get_check_compliance as via_finding

        assert via_finding is via_helper

    def test_returns_empty_dict_on_unknown_check(self):
        """Sanity test of the function logic via the helper module."""
        from prowler.lib.outputs.compliance.compliance_check import (
            get_check_compliance,
        )

        finding = mock.MagicMock()
        finding.check_metadata.CheckID = "unknown_check_id"
        result = get_check_compliance(finding, "aws", {})
        assert result == {}

    def test_filters_by_provider(self):
        """The function returns frameworks only for the matching provider."""
        from prowler.lib.outputs.compliance.compliance_check import (
            get_check_compliance,
        )

        compliance_aws = mock.MagicMock(
            Framework="CIS",
            Version="1.4",
            Provider="AWS",
            Requirements=[mock.MagicMock(Id="2.1.3")],
        )
        compliance_azure = mock.MagicMock(
            Framework="CIS",
            Version="2.0",
            Provider="Azure",
            Requirements=[mock.MagicMock(Id="9.1")],
        )
        finding = mock.MagicMock()
        finding.check_metadata.CheckID = "shared_check"
        bulk = {
            "shared_check": mock.MagicMock(
                Compliance=[compliance_aws, compliance_azure]
            )
        }

        # Only AWS frameworks come back
        result = get_check_compliance(finding, "aws", bulk)
        assert "CIS-1.4" in result
        assert "CIS-2.0" not in result

    def test_returns_empty_dict_on_exception(self):
        """If iteration raises, the function logs the error and returns
        an empty dict (defensive behaviour)."""
        from prowler.lib.outputs.compliance.compliance_check import (
            get_check_compliance,
        )

        # bulk_checks_metadata that raises when accessed → defensive path
        class Boom:
            def __contains__(self, _key):
                raise RuntimeError("boom")

        finding = mock.MagicMock()
        finding.check_metadata.CheckID = "any"
        result = get_check_compliance(finding, "aws", Boom())
        assert result == {}
