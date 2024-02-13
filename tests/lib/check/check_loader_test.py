from mock import patch

from prowler.lib.check.checks_loader import (
    load_checks_to_execute,
    update_checks_to_execute_with_aliases,
)
from prowler.lib.check.models import (
    Check_Metadata_Model,
    Code,
    Recommendation,
    Remediation,
)

S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME = "s3_bucket_level_public_access_block"
S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME_CUSTOM_ALIAS = (
    "s3_bucket_level_public_access_block"
)
S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_SEVERITY = "medium"
S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME_SERVICE = "s3"


class TestCheckLoader:
    provider = "aws"

    def get_custom_check_metadata(self):
        return Check_Metadata_Model(
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
                    Terraform="https://docs.bridgecrew.io/docs/bc_aws_s3_20#terraform",
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

    def test_load_checks_to_execute(self):
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_metadata()
        }
        bulk_compliance_frameworks = None
        checks_file = None
        check_list = None
        service_list = None
        severities = None
        compliance_frameworks = None
        categories = None

        with patch(
            "prowler.lib.check.checks_loader.recover_checks_from_provider",
            return_value=[
                (
                    f"{S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME}",
                    "path/to/{S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME}",
                )
            ],
        ):
            assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
                bulk_checks_metatada,
                bulk_compliance_frameworks,
                checks_file,
                check_list,
                service_list,
                severities,
                compliance_frameworks,
                categories,
                self.provider,
            )

    def test_load_checks_to_execute_with_check_list(self):
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_metadata()
        }
        bulk_compliance_frameworks = None
        checks_file = None
        check_list = [S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME]
        service_list = None
        severities = None
        compliance_frameworks = None
        categories = None

        assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
            bulk_checks_metatada,
            bulk_compliance_frameworks,
            checks_file,
            check_list,
            service_list,
            severities,
            compliance_frameworks,
            categories,
            self.provider,
        )

    def test_load_checks_to_execute_with_severities(self):
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_metadata()
        }
        bulk_compliance_frameworks = None
        checks_file = None
        check_list = []
        service_list = None
        severities = [S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_SEVERITY]
        compliance_frameworks = None
        categories = None

        assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
            bulk_checks_metatada,
            bulk_compliance_frameworks,
            checks_file,
            check_list,
            service_list,
            severities,
            compliance_frameworks,
            categories,
            self.provider,
        )

    def test_load_checks_to_execute_with_severities_and_services(self):
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_metadata()
        }
        bulk_compliance_frameworks = None
        checks_file = None
        check_list = []
        service_list = [S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME_SERVICE]
        severities = [S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_SEVERITY]
        compliance_frameworks = None
        categories = None

        with patch(
            "prowler.lib.check.checks_loader.recover_checks_from_service",
            return_value={S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME},
        ):
            assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
                bulk_checks_metatada,
                bulk_compliance_frameworks,
                checks_file,
                check_list,
                service_list,
                severities,
                compliance_frameworks,
                categories,
                self.provider,
            )

    def test_load_checks_to_execute_with_severities_and_services_not_within_severity(
        self,
    ):
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_metadata()
        }
        bulk_compliance_frameworks = None
        checks_file = None
        check_list = []
        service_list = ["ec2"]
        severities = [S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_SEVERITY]
        compliance_frameworks = None
        categories = None

        with patch(
            "prowler.lib.check.checks_loader.recover_checks_from_service",
            return_value={"ec2_ami_public"},
        ):
            assert set() == load_checks_to_execute(
                bulk_checks_metatada,
                bulk_compliance_frameworks,
                checks_file,
                check_list,
                service_list,
                severities,
                compliance_frameworks,
                categories,
                self.provider,
            )

    def test_load_checks_to_execute_with_checks_file(
        self,
    ):
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_metadata()
        }
        bulk_compliance_frameworks = None
        checks_file = "path/to/test_file"
        check_list = []
        service_list = []
        severities = []
        compliance_frameworks = None
        categories = None

        with patch(
            "prowler.lib.check.checks_loader.parse_checks_from_file",
            return_value={S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME},
        ):
            assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
                bulk_checks_metatada,
                bulk_compliance_frameworks,
                checks_file,
                check_list,
                service_list,
                severities,
                compliance_frameworks,
                categories,
                self.provider,
            )

    def test_load_checks_to_execute_with_service_list(
        self,
    ):
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_metadata()
        }
        bulk_compliance_frameworks = None
        checks_file = None
        check_list = []
        service_list = [S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME_SERVICE]
        severities = []
        compliance_frameworks = None
        categories = None

        with patch(
            "prowler.lib.check.checks_loader.recover_checks_from_service",
            return_value={S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME},
        ):
            assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
                bulk_checks_metatada,
                bulk_compliance_frameworks,
                checks_file,
                check_list,
                service_list,
                severities,
                compliance_frameworks,
                categories,
                self.provider,
            )

    def test_load_checks_to_execute_with_compliance_frameworks(
        self,
    ):
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_metadata()
        }
        bulk_compliance_frameworks = None
        checks_file = None
        check_list = []
        service_list = []
        severities = []
        compliance_frameworks = ["test-compliance-framework"]
        categories = None

        with patch(
            "prowler.lib.check.checks_loader.parse_checks_from_compliance_framework",
            return_value={S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME},
        ):
            assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
                bulk_checks_metatada,
                bulk_compliance_frameworks,
                checks_file,
                check_list,
                service_list,
                severities,
                compliance_frameworks,
                categories,
                self.provider,
            )

    def test_load_checks_to_execute_with_categories(
        self,
    ):
        bulk_checks_metatada = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_metadata()
        }
        bulk_compliance_frameworks = None
        checks_file = None
        check_list = []
        service_list = []
        severities = []
        compliance_frameworks = []
        categories = {"internet-exposed"}

        assert {S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME} == load_checks_to_execute(
            bulk_checks_metatada,
            bulk_compliance_frameworks,
            checks_file,
            check_list,
            service_list,
            severities,
            compliance_frameworks,
            categories,
            self.provider,
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
