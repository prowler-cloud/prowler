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

CLOUDTRAIL_THREAT_DETECTION_ENUMERATION_NAME = "cloudtrail_threat_detection_enumeration"


class TestCheckLoader:
    provider = "aws"

    def get_custom_check_s3_metadata(self):
        return CheckMetadata(
            Provider="aws",
            CheckID=S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME,
            CheckTitle="Check S3 Bucket Level Public Access Block.",
            CheckType=["Data Protection"],
            CheckAliases=[S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME_CUSTOM_ALIAS],
            ServiceName=S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME_SERVICE,
            SubServiceName="",
            ResourceIdTemplate="arn:partition:s3:::bucket_name",
            Severity=S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_SEVERITY,
            ResourceType="AwsS3Bucket",
            Description="Check S3 Bucket Level Public Access Block.",
            Risk="Public access policies may be applied to sensitive data buckets.",
            RelatedUrl="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
            Remediation=Remediation(
                Code=Code(
                    NativeIaC="",
                    Terraform="https://docs.prowler.com/checks/aws/s3-policies/bc_aws_s3_20#terraform",
                    CLI="aws s3api put-public-access-block --region <REGION_NAME> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true --bucket <BUCKET_NAME>",
                    Other="https://github.com/cloudmatos/matos/tree/master/remediations/aws/s3/s3/block-public-access",
                ),
                Recommendation=Recommendation(
                    Text="You can enable Public Access Block at the bucket level to prevent the exposure of your data stored in S3.",
                    Url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                ),
            ),
            Categories=["internet-exposed"],
            DependsOn=[],
            RelatedTo=[],
            Notes="",
            Compliance=[],
        )

    def get_threat_detection_check_metadata(self):
        return CheckMetadata(
            Provider="aws",
            CheckID=CLOUDTRAIL_THREAT_DETECTION_ENUMERATION_NAME,
            CheckTitle="Ensure there are no potential enumeration threats in CloudTrail",
            CheckType=[],
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
                    Url="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html#cloudtrail-concepts-logging-data-events",
                ),
            ),
            Categories=["threat-detection"],
            DependsOn=[],
            RelatedTo=[],
            Notes="",
            Compliance=[],
        )

    def test_load_checks_to_execute(self):
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }

        assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
            bulk_checks_metadata=bulk_checks_metatada,
            provider=self.provider,
        )

    def test_load_checks_to_execute_with_check_list(self):
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        check_list = [S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME]

        assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
            bulk_checks_metadata=bulk_checks_metatada,
            check_list=check_list,
            provider=self.provider,
        )

    def test_load_checks_to_execute_with_severities(self):
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        severities = [S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_SEVERITY]

        assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
            bulk_checks_metadata=bulk_checks_metatada,
            severities=severities,
            provider=self.provider,
        )

    def test_load_checks_to_execute_with_severities_and_services(self):
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        service_list = [S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME_SERVICE]
        severities = [S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_SEVERITY]

        assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
            bulk_checks_metadata=bulk_checks_metatada,
            service_list=service_list,
            severities=severities,
            provider=self.provider,
        )

    def test_load_checks_to_execute_with_severities_and_services_not_within_severity(
        self,
    ):
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        service_list = ["ec2"]
        severities = [S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_SEVERITY]

        assert set() == load_checks_to_execute(
            bulk_checks_metadata=bulk_checks_metatada,
            service_list=service_list,
            severities=severities,
            provider=self.provider,
        )

    def test_load_checks_to_execute_with_checks_file(
        self,
    ):
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        checks_file = "path/to/test_file"
        with patch(
            "prowler.lib.check.checks_loader.parse_checks_from_file",
            return_value={S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME},
        ):
            assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
                bulk_checks_metadata=bulk_checks_metatada,
                checks_file=checks_file,
                provider=self.provider,
            )

    def test_load_checks_to_execute_with_service_list(
        self,
    ):
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        service_list = [S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME_SERVICE]

        assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
            bulk_checks_metadata=bulk_checks_metatada,
            service_list=service_list,
            provider=self.provider,
        )

    def test_load_checks_to_execute_with_compliance_frameworks(
        self,
    ):
        bulk_compliance_frameworks = {
            "soc2_aws": Compliance(
                Framework="SOC2",
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

        assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
            bulk_compliance_frameworks=bulk_compliance_frameworks,
            compliance_frameworks=compliance_frameworks,
            provider=self.provider,
        )

    def test_load_checks_to_execute_with_categories(
        self,
    ):
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        categories = {"internet-exposed"}

        assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
            bulk_checks_metadata=bulk_checks_metatada,
            categories=categories,
            provider=self.provider,
        )

    def test_load_checks_to_execute_no_bulk_checks_metadata(self):
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        with patch(
            "prowler.lib.check.checks_loader.CheckMetadata.get_bulk",
            return_value=bulk_checks_metatada,
        ):
            assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
                provider=self.provider,
            )

    def test_load_checks_to_execute_no_bulk_compliance_frameworks(self):
        bulk_compliance_frameworks = {
            "soc2_aws": Compliance(
                Framework="SOC2",
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

        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_s3_metadata()
        }
        with patch(
            "prowler.lib.check.checks_loader.CheckMetadata.get_bulk",
            return_value=bulk_checks_metatada,
        ), patch(
            "prowler.lib.check.checks_loader.Compliance.get_bulk",
            return_value=bulk_compliance_frameworks,
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
        bulk_checks_metatada = {
            CLOUDTRAIL_THREAT_DETECTION_ENUMERATION_NAME: self.get_threat_detection_check_metadata()
        }
        categories = {"threat-detection"}

        assert {CLOUDTRAIL_THREAT_DETECTION_ENUMERATION_NAME} == load_checks_to_execute(
            bulk_checks_metadata=bulk_checks_metatada,
            categories=categories,
            provider=self.provider,
        )

    def test_discard_threat_detection_checks(self):
        bulk_checks_metatada = {
            CLOUDTRAIL_THREAT_DETECTION_ENUMERATION_NAME: self.get_threat_detection_check_metadata()
        }
        categories = {}

        assert set() == load_checks_to_execute(
            bulk_checks_metadata=bulk_checks_metatada,
            categories=categories,
            provider=self.provider,
        )
