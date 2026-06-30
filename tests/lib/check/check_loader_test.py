import pytest
from mock import patch

from prowler.lib.check.checks_loader import (
    load_checks_to_execute,
    update_checks_to_execute_with_aliases,
)
from prowler.lib.check.compliance_models import Compliance, Compliance_Requirement
from prowler.lib.check.models import CheckMetadata, Code, Recommendation, Remediation

S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME = "s3_bucket_level_public_access_block"
S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME_CUSTOM_ALIAS = (
    "s3_bucket_level_public_access_block"
)
S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_SEVERITY = "medium"
S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME_SERVICE = "s3"

IAM_USER_NO_MFA_NAME = "iam_user_no_mfa"
IAM_USER_NO_MFA_NAME_CUSTOM_ALIAS = "iam_user_no_mfa"
IAM_USER_NO_MFA_NAME_SERVICE = "iam"
IAM_USER_NO_MFA_SEVERITY = "high"

CLOUDTRAIL_THREAT_DETECTION_ENUMERATION_NAME = "cloudtrail_threat_detection_enumeration"


class TestCheckLoader:
    provider = "aws"

    def get_custom_check_s3_metadata(self):
        return CheckMetadata(
            Provider="aws",
            CheckID=S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME,
            CheckTitle="Check S3 Bucket Level Public Access Block.",
            CheckType=[
                "Software and Configuration Checks/AWS Security Best Practices/Network Reachability"
            ],
            CheckAliases=[S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME_CUSTOM_ALIAS],
            ServiceName=S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME_SERVICE,
            SubServiceName="",
            ResourceIdTemplate="arn:partition:s3:::bucket_name",
            Severity=S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_SEVERITY,
            ResourceType="AwsS3Bucket",
            ResourceGroup="storage",
            Description="Check S3 Bucket Level Public Access Block.",
            Risk="Public access policies may be applied to sensitive data buckets.",
            RelatedUrl="",
            Remediation=Remediation(
                Code=Code(
                    NativeIaC="",
                    Terraform="https://docs.prowler.com/checks/aws/s3-policies/bc_aws_s3_20#terraform",
                    CLI="aws s3api put-public-access-block --region <REGION_NAME> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true --bucket <BUCKET_NAME>",
                    Other="https://github.com/cloudmatos/matos/tree/master/remediations/aws/s3/s3/block-public-access",
                ),
                Recommendation=Recommendation(
                    Text="You can enable Public Access Block at the bucket level to prevent the exposure of your data stored in S3.",
                    Url="https://hub.prowler.com/check/s3_bucket_level_public_access_block",
                ),
            ),
            Categories=["internet-exposed"],
            DependsOn=[],
            RelatedTo=[],
            Notes="",
            Compliance=[],
        )

    def get_custom_check_iam_metadata(self):
        return CheckMetadata(
            Provider="aws",
            CheckID=IAM_USER_NO_MFA_NAME,
            CheckTitle="Check IAM User No MFA.",
            CheckType=[
                "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark"
            ],
            CheckAliases=[IAM_USER_NO_MFA_NAME_CUSTOM_ALIAS],
            ServiceName=IAM_USER_NO_MFA_NAME_SERVICE,
            SubServiceName="",
            ResourceIdTemplate="arn:partition:iam::account-id:user/user_name",
            Severity=IAM_USER_NO_MFA_SEVERITY,
            ResourceType="AwsIamUser",
            ResourceGroup="IAM",
            Description="Check IAM User No MFA.",
            Risk="IAM users should have Multi-Factor Authentication (MFA) enabled.",
            RelatedUrl="",
            Remediation=Remediation(
                Code=Code(
                    NativeIaC="",
                    Terraform="https://docs.prowler.com/checks/aws/iam-policies/bc_aws_iam_20#terraform",
                    CLI="aws iam create-virtual-mfa-device --user-name <USER_NAME> --serial-number <SERIAL_NUMBER>",
                    Other="https://github.com/cloudmatos/matos/tree/master/remediations/aws/iam/iam/enable-mfa",
                ),
                Recommendation=Recommendation(
                    Text="You can enable MFA for your IAM user to prevent unauthorized access to your AWS account.",
                    Url="https://hub.prowler.com/check/iam_user_no_mfa",
                ),
            ),
            Categories=[],
            DependsOn=[],
            RelatedTo=[],
            Notes="",
            Compliance=[],
        )

    def get_threat_detection_check_metadata(self):
        return CheckMetadata(
            Provider="aws",
            CheckID=CLOUDTRAIL_THREAT_DETECTION_ENUMERATION_NAME,
            CheckTitle="CloudTrail should not have potential enumeration threats",
            CheckType=["TTPs/Discovery"],
            ServiceName="cloudtrail",
            SubServiceName="",
            ResourceIdTemplate="arn:partition:service:region:account-id:resource-id",
            Severity="critical",
            ResourceType="AwsCloudTrailTrail",
            Description="This check ensures that there are no potential enumeration threats in CloudTrail.",
            Risk="Potential enumeration threats in CloudTrail can lead to unauthorized access to resources.",
            RelatedUrl="",
            Remediation=Remediation(
                Code=Code(CLI="", NativeIaC="", Other="", Terraform=""),
                Recommendation=Recommendation(
                    Text="To remediate this issue, ensure that there are no potential enumeration threats in CloudTrail.",
                    Url="https://hub.prowler.com/check/cloudtrail_threat_detection_enumeration",
                ),
            ),
            Categories=["threat-detection"],
            DependsOn=[],
            RelatedTo=[],
            Notes="",
            Compliance=[],
        )

    def test_load_checks_to_execute(self):
        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }

        assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
            bulk_checks_metadata=bulk_checks_metadata,
            provider=self.provider,
        )

    def test_load_checks_to_execute_with_check_list(self):
        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        check_list = [S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME]

        assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
            bulk_checks_metadata=bulk_checks_metadata,
            check_list=check_list,
            provider=self.provider,
        )

    def test_load_checks_to_execute_with_severities(self):
        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        severities = [S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_SEVERITY]

        assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
            bulk_checks_metadata=bulk_checks_metadata,
            severities=severities,
            provider=self.provider,
        )

    def test_load_checks_to_execute_with_severities_and_services(self):
        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        service_list = [S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME_SERVICE]
        severities = [S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_SEVERITY]

        assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
            bulk_checks_metadata=bulk_checks_metadata,
            service_list=service_list,
            severities=severities,
            provider=self.provider,
        )

    def test_load_checks_to_execute_with_severities_and_services_multiple(self):
        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata(),
            IAM_USER_NO_MFA_NAME: self.get_custom_check_iam_metadata(),
        }
        service_list = ["s3", "iam"]
        severities = ["medium", "high"]

        assert {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME,
            IAM_USER_NO_MFA_NAME,
        } == load_checks_to_execute(
            bulk_checks_metadata=bulk_checks_metadata,
            service_list=service_list,
            severities=severities,
            provider=self.provider,
        )

    def test_load_checks_to_execute_with_severities_and_services_not_within_severity(
        self,
    ):
        """Test that service not in metadata causes sys.exit(1) when used with severities"""
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        service_list = ["ec2"]
        severities = [S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_SEVERITY]

        # ec2 service doesn't exist in the metadata, so it should exit with error
        with pytest.raises(SystemExit) as exc_info:
            load_checks_to_execute(
                bulk_checks_metadata=bulk_checks_metatada,
                service_list=service_list,
                severities=severities,
                provider=self.provider,
            )
        assert exc_info.value.code == 1

    def test_load_checks_to_execute_with_checks_file(
        self,
    ):
        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        checks_file = "path/to/test_file"
        with patch(
            "prowler.lib.check.checks_loader.parse_checks_from_file",
            return_value={S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME},
        ):
            assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
                bulk_checks_metadata=bulk_checks_metadata,
                checks_file=checks_file,
                provider=self.provider,
            )

    def test_load_checks_to_execute_with_service_list(
        self,
    ):
        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        service_list = [S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME_SERVICE]

        assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
            bulk_checks_metadata=bulk_checks_metadata,
            service_list=service_list,
            provider=self.provider,
        )

    def test_load_checks_to_execute_with_compliance_frameworks(
        self,
    ):
        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        bulk_compliance_frameworks = {
            "soc2_aws": Compliance(
                Framework="SOC2",
                Name="SOC2",
                Provider="aws",
                Version="2.0",
                Description="This CIS Benchmark is the product of a community consensus process and consists of secure configuration guidelines developed for Azuee Platform",
                Requirements=[
                    Compliance_Requirement(
                        Checks=[S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME],
                        Id="",
                        Description="",
                        Attributes=[],
                    )
                ],
            ),
        }
        compliance_frameworks = ["soc2_aws"]

        # Mock get_bulk to prevent loading real metadata files that may fail validation
        with patch(
            "prowler.lib.check.checks_loader.CheckMetadata.get_bulk",
            return_value=bulk_checks_metadata,
        ):
            assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
                bulk_checks_metadata=bulk_checks_metadata,
                bulk_compliance_frameworks=bulk_compliance_frameworks,
                compliance_frameworks=compliance_frameworks,
                provider=self.provider,
            )

    def test_load_checks_to_execute_with_categories(
        self,
    ):
        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        categories = {"internet-exposed"}

        assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
            bulk_checks_metadata=bulk_checks_metadata,
            categories=categories,
            provider=self.provider,
        )

    def test_load_checks_to_execute_no_bulk_checks_metadata(self):
        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        with patch(
            "prowler.lib.check.checks_loader.CheckMetadata.get_bulk",
            return_value=bulk_checks_metadata,
        ):
            assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
                provider=self.provider,
            )

    def test_load_checks_to_execute_no_bulk_compliance_frameworks(self):
        bulk_compliance_frameworks = {
            "soc2_aws": Compliance(
                Framework="SOC2",
                Name="SOC2",
                Provider="aws",
                Version="2.0",
                Description="This CIS Benchmark is the product of a community consensus process and consists of secure configuration guidelines developed for Azuee Platform",
                Requirements=[
                    Compliance_Requirement(
                        Checks=[S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME],
                        Id="",
                        Description="",
                        Attributes=[],
                    )
                ],
            ),
        }

        compliance_frameworks = ["soc2_aws"]

        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        with (
            patch(
                "prowler.lib.check.checks_loader.CheckMetadata.get_bulk",
                return_value=bulk_checks_metadata,
            ),
            patch(
                "prowler.lib.check.checks_loader.Compliance.get_bulk",
                return_value=bulk_compliance_frameworks,
            ),
        ):
            assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
                compliance_frameworks=compliance_frameworks,
                provider=self.provider,
            )

    def test_update_checks_to_execute_with_aliases(self):
        checks_to_execute = {"renamed_check"}
        check_aliases = {"renamed_check": ["check_name"]}
        assert {"check_name"} == update_checks_to_execute_with_aliases(
            checks_to_execute, check_aliases
        )

    def test_update_checks_to_execute_with_multiple_aliases(self):
        checks_to_execute = {"renamed_check"}
        check_aliases = {"renamed_check": ["check1_name", "check2_name"]}
        assert {"check1_name", "check2_name"} == update_checks_to_execute_with_aliases(
            checks_to_execute, check_aliases
        )

    def test_threat_detection_category(self):
        bulk_checks_metadata = {
            CLOUDTRAIL_THREAT_DETECTION_ENUMERATION_NAME: self.get_threat_detection_check_metadata()
        }
        categories = {"threat-detection"}

        assert {CLOUDTRAIL_THREAT_DETECTION_ENUMERATION_NAME} == load_checks_to_execute(
            bulk_checks_metadata=bulk_checks_metadata,
            categories=categories,
            provider=self.provider,
        )

    def test_discard_threat_detection_checks(self):
        bulk_checks_metadata = {
            CLOUDTRAIL_THREAT_DETECTION_ENUMERATION_NAME: self.get_threat_detection_check_metadata()
        }
        categories = {}

        assert set() == load_checks_to_execute(
            bulk_checks_metadata=bulk_checks_metadata,
            categories=categories,
            provider=self.provider,
        )

    def test_threat_detection_single_check(self):
        bulk_checks_metadata = {
            CLOUDTRAIL_THREAT_DETECTION_ENUMERATION_NAME: self.get_threat_detection_check_metadata()
        }
        categories = {}
        check_list = [CLOUDTRAIL_THREAT_DETECTION_ENUMERATION_NAME]

        assert {CLOUDTRAIL_THREAT_DETECTION_ENUMERATION_NAME} == load_checks_to_execute(
            bulk_checks_metadata=bulk_checks_metadata,
            check_list=check_list,
            categories=categories,
            provider=self.provider,
        )

    def test_load_checks_to_execute_with_invalid_check(self):
        """Test that invalid check names cause sys.exit(1)"""
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        check_list = ["invalid_check_name"]

        with pytest.raises(SystemExit) as exc_info:
            load_checks_to_execute(
                bulk_checks_metadata=bulk_checks_metatada,
                check_list=check_list,
                provider=self.provider,
            )
        assert exc_info.value.code == 1

    def test_load_checks_to_execute_with_multiple_invalid_checks(self):
        """Test that multiple invalid check names cause sys.exit(1)"""
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        check_list = ["invalid_check_1", "invalid_check_2", "invalid_check_3"]

        with pytest.raises(SystemExit) as exc_info:
            load_checks_to_execute(
                bulk_checks_metadata=bulk_checks_metatada,
                check_list=check_list,
                provider=self.provider,
            )
        assert exc_info.value.code == 1

    def test_load_checks_to_execute_with_mixed_valid_invalid_checks(self):
        """Test that mix of valid and invalid checks cause sys.exit(1)"""
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        check_list = [S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME, "invalid_check"]

        with pytest.raises(SystemExit) as exc_info:
            load_checks_to_execute(
                bulk_checks_metadata=bulk_checks_metatada,
                check_list=check_list,
                provider=self.provider,
            )
        assert exc_info.value.code == 1

    def test_load_checks_to_execute_with_invalid_service(self):
        """Test that invalid service names cause sys.exit(1)"""
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        service_list = ["invalid_service"]

        with pytest.raises(SystemExit) as exc_info:
            load_checks_to_execute(
                bulk_checks_metadata=bulk_checks_metatada,
                service_list=service_list,
                provider=self.provider,
            )
        assert exc_info.value.code == 1

    def test_load_checks_to_execute_with_invalid_service_and_severity(self):
        """Test that invalid service names with severity cause sys.exit(1)"""
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        service_list = ["invalid_service"]
        severities = [S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_SEVERITY]

        with pytest.raises(SystemExit) as exc_info:
            load_checks_to_execute(
                bulk_checks_metadata=bulk_checks_metatada,
                service_list=service_list,
                severities=severities,
                provider=self.provider,
            )
        assert exc_info.value.code == 1

    def test_load_checks_to_execute_with_multiple_invalid_services(self):
        """Test that multiple invalid service names cause sys.exit(1)"""
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        service_list = ["invalid_service_1", "invalid_service_2"]

        with pytest.raises(SystemExit) as exc_info:
            load_checks_to_execute(
                bulk_checks_metadata=bulk_checks_metatada,
                service_list=service_list,
                provider=self.provider,
            )
        assert exc_info.value.code == 1

    def test_load_checks_to_execute_with_invalid_category(self):
        """Test that invalid category names cause sys.exit(1)"""
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        categories = {"invalid_category"}

        with pytest.raises(SystemExit) as exc_info:
            load_checks_to_execute(
                bulk_checks_metadata=bulk_checks_metatada,
                categories=categories,
                provider=self.provider,
            )
        assert exc_info.value.code == 1

    def test_load_checks_to_execute_with_multiple_invalid_categories(self):
        """Test that multiple invalid category names cause sys.exit(1)"""
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        categories = {"invalid_category_1", "invalid_category_2"}

        with pytest.raises(SystemExit) as exc_info:
            load_checks_to_execute(
                bulk_checks_metadata=bulk_checks_metatada,
                categories=categories,
                provider=self.provider,
            )
        assert exc_info.value.code == 1

    def test_load_checks_to_execute_with_mixed_valid_invalid_categories(self):
        """Test that mix of valid and invalid categories cause sys.exit(1)"""
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        categories = {"internet-exposed", "invalid_category"}

        with pytest.raises(SystemExit) as exc_info:
            load_checks_to_execute(
                bulk_checks_metadata=bulk_checks_metatada,
                categories=categories,
                provider=self.provider,
            )
        assert exc_info.value.code == 1

    def test_load_checks_to_execute_with_resource_groups(self):
        """Test that checks are filtered by resource group"""
        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata(),
            IAM_USER_NO_MFA_NAME: self.get_custom_check_iam_metadata(),
        }
        resource_groups = {"storage"}

        assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
            bulk_checks_metadata=bulk_checks_metadata,
            resource_groups=resource_groups,
            provider=self.provider,
        )

    def test_load_checks_to_execute_with_multiple_resource_groups(self):
        """Test that checks are filtered by multiple resource groups"""
        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata(),
            IAM_USER_NO_MFA_NAME: self.get_custom_check_iam_metadata(),
        }
        resource_groups = {"storage", "IAM"}

        assert {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME,
            IAM_USER_NO_MFA_NAME,
        } == load_checks_to_execute(
            bulk_checks_metadata=bulk_checks_metadata,
            resource_groups=resource_groups,
            provider=self.provider,
        )

    def test_load_checks_to_execute_with_resource_group_case_insensitive(self):
        """Test that resource group matching is case-insensitive"""
        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata(),
            IAM_USER_NO_MFA_NAME: self.get_custom_check_iam_metadata(),
        }
        # "iam" lowercase should match metadata "IAM", "Storage" mixed case should match "storage"
        resource_groups = {"iam", "Storage"}

        assert {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME,
            IAM_USER_NO_MFA_NAME,
        } == load_checks_to_execute(
            bulk_checks_metadata=bulk_checks_metadata,
            resource_groups=resource_groups,
            provider=self.provider,
        )

    def test_load_checks_to_execute_with_invalid_resource_group(self):
        """Test that invalid resource group names cause sys.exit(1)"""
        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        resource_groups = {"invalid_resource_group"}

        with pytest.raises(SystemExit) as exc_info:
            load_checks_to_execute(
                bulk_checks_metadata=bulk_checks_metadata,
                resource_groups=resource_groups,
                provider=self.provider,
            )
        assert exc_info.value.code == 1

    def test_load_checks_to_execute_with_multiple_invalid_resource_groups(self):
        """Test that multiple invalid resource group names cause sys.exit(1)"""
        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        resource_groups = {"invalid_rg_1", "invalid_rg_2"}

        with pytest.raises(SystemExit) as exc_info:
            load_checks_to_execute(
                bulk_checks_metadata=bulk_checks_metadata,
                resource_groups=resource_groups,
                provider=self.provider,
            )
        assert exc_info.value.code == 1

    def test_load_checks_to_execute_with_mixed_valid_invalid_resource_groups(self):
        """Test that mix of valid and invalid resource groups cause sys.exit(1)"""
        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        resource_groups = {"storage", "invalid_resource_group"}

        with pytest.raises(SystemExit) as exc_info:
            load_checks_to_execute(
                bulk_checks_metadata=bulk_checks_metadata,
                resource_groups=resource_groups,
                provider=self.provider,
            )
        assert exc_info.value.code == 1

    def test_list_checks_includes_threat_detection(self):
        """Test that list_checks=True includes threat-detection checks (fixes #10576)"""
        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata(),
            CLOUDTRAIL_THREAT_DETECTION_ENUMERATION_NAME: self.get_threat_detection_check_metadata(),
        }

        result = load_checks_to_execute(
            bulk_checks_metadata=bulk_checks_metadata,
            provider=self.provider,
            list_checks=True,
        )
        assert CLOUDTRAIL_THREAT_DETECTION_ENUMERATION_NAME in result
        assert S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME in result

    def test_list_checks_with_service_includes_threat_detection(self):
        """Test that list_checks=True with service filter includes threat-detection checks (fixes #10576)"""
        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata(),
            CLOUDTRAIL_THREAT_DETECTION_ENUMERATION_NAME: self.get_threat_detection_check_metadata(),
        }
        service_list = ["cloudtrail"]

        result = load_checks_to_execute(
            bulk_checks_metadata=bulk_checks_metadata,
            service_list=service_list,
            provider=self.provider,
            list_checks=True,
        )
        assert CLOUDTRAIL_THREAT_DETECTION_ENUMERATION_NAME in result
        assert S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME not in result

    def test_scan_still_excludes_threat_detection_by_default(self):
        """Test that without list_checks, threat-detection checks are still excluded"""
        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata(),
            CLOUDTRAIL_THREAT_DETECTION_ENUMERATION_NAME: self.get_threat_detection_check_metadata(),
        }

        result = load_checks_to_execute(
            bulk_checks_metadata=bulk_checks_metadata,
            provider=self.provider,
        )
        assert CLOUDTRAIL_THREAT_DETECTION_ENUMERATION_NAME not in result
        assert S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME in result

    def test_load_checks_to_execute_universal_framework_takes_precedence(self):
        """When ``--compliance <fw>`` matches a universal framework, the
        loader must source checks from ``universal_frameworks[fw].requirements[*]
        .checks[provider]`` and NOT fall through to ``bulk_compliance_frameworks``.

        This is the path added by PR #10301 in checks_loader.py.
        """
        from prowler.lib.check.compliance_models import (
            ComplianceFramework,
            UniversalComplianceRequirement,
        )

        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }

        universal_framework = ComplianceFramework(
            framework="csa_ccm",
            name="CSA CCM 4.0",
            version="4.0",
            description="Cloud Controls Matrix",
            requirements=[
                UniversalComplianceRequirement(
                    id="A&A-01",
                    description="Audit & Assurance",
                    attributes={},
                    checks={"aws": [S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME]},
                ),
            ],
        )

        with patch(
            "prowler.lib.check.checks_loader.CheckMetadata.get_bulk",
            return_value=bulk_checks_metadata,
        ):
            result = load_checks_to_execute(
                bulk_checks_metadata=bulk_checks_metadata,
                bulk_compliance_frameworks={},  # legacy empty
                compliance_frameworks=["csa_ccm_4.0"],
                provider=self.provider,
                universal_frameworks={"csa_ccm_4.0": universal_framework},
            )

        assert result == {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME}

    def test_load_checks_to_execute_universal_filters_by_provider(self):
        """A universal requirement may declare checks for several
        providers; the loader must only return those for the active
        provider key (lowercased)."""
        from prowler.lib.check.compliance_models import (
            ComplianceFramework,
            UniversalComplianceRequirement,
        )

        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }

        # The same requirement maps a different check per provider.
        # Only the AWS one must be returned for provider="aws".
        universal_framework = ComplianceFramework(
            framework="csa_ccm",
            name="CSA CCM 4.0",
            version="4.0",
            description="Cloud Controls Matrix",
            requirements=[
                UniversalComplianceRequirement(
                    id="A&A-02",
                    description="Multi-provider req",
                    attributes={},
                    checks={
                        "aws": [S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME],
                        "azure": ["azure_only_check"],
                        "gcp": ["gcp_only_check"],
                    },
                ),
            ],
        )

        with patch(
            "prowler.lib.check.checks_loader.CheckMetadata.get_bulk",
            return_value=bulk_checks_metadata,
        ):
            result = load_checks_to_execute(
                bulk_checks_metadata=bulk_checks_metadata,
                bulk_compliance_frameworks={},
                compliance_frameworks=["csa_ccm_4.0"],
                provider=self.provider,  # "aws"
                universal_frameworks={"csa_ccm_4.0": universal_framework},
            )

        assert S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME in result
        assert "azure_only_check" not in result
        assert "gcp_only_check" not in result

    def test_load_checks_to_execute_universal_no_match_falls_back_to_legacy(self):
        """If the requested compliance framework is not present in
        ``universal_frameworks``, the loader must fall back to the
        legacy ``bulk_compliance_frameworks`` lookup."""
        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        bulk_compliance_frameworks = {
            "soc2_aws": Compliance(
                Framework="SOC2",
                Name="SOC2",
                Provider="aws",
                Version="2.0",
                Description="x",
                Requirements=[
                    Compliance_Requirement(
                        Checks=[S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME],
                        Id="",
                        Description="",
                        Attributes=[],
                    )
                ],
            ),
        }

        with patch(
            "prowler.lib.check.checks_loader.CheckMetadata.get_bulk",
            return_value=bulk_checks_metadata,
        ):
            result = load_checks_to_execute(
                bulk_checks_metadata=bulk_checks_metadata,
                bulk_compliance_frameworks=bulk_compliance_frameworks,
                compliance_frameworks=["soc2_aws"],
                provider=self.provider,
                universal_frameworks={"some_other_universal_fw": object()},
            )

        assert result == {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME}

    def test_load_checks_to_execute_universal_unknown_provider_returns_empty(self):
        """If the universal requirement has no checks for the active
        provider, no checks are picked up for that requirement."""
        from prowler.lib.check.compliance_models import (
            ComplianceFramework,
            UniversalComplianceRequirement,
        )

        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        universal_framework = ComplianceFramework(
            framework="csa_ccm",
            name="CSA CCM 4.0",
            version="4.0",
            description="Cloud Controls Matrix",
            requirements=[
                UniversalComplianceRequirement(
                    id="A&A-03",
                    description="Only Azure",
                    attributes={},
                    checks={"azure": ["azure_only_check"]},
                ),
            ],
        )

        with patch(
            "prowler.lib.check.checks_loader.CheckMetadata.get_bulk",
            return_value=bulk_checks_metadata,
        ):
            result = load_checks_to_execute(
                bulk_checks_metadata=bulk_checks_metadata,
                bulk_compliance_frameworks={},
                compliance_frameworks=["csa_ccm_4.0"],
                provider=self.provider,  # "aws" — no checks declared
                universal_frameworks={"csa_ccm_4.0": universal_framework},
            )

        assert result == set()
