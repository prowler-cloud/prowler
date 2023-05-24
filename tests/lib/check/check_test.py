import os
import pathlib
from importlib.machinery import FileFinder
from pkgutil import ModuleInfo

from boto3 import client, session
from mock import patch
from moto import mock_s3

from prowler.lib.check.check import (
    exclude_checks_to_run,
    exclude_services_to_run,
    list_categories,
    list_modules,
    list_services,
    parse_checks_from_file,
    parse_checks_from_folder,
    recover_checks_from_provider,
    recover_checks_from_service,
    remove_custom_checks_module,
    update_audit_metadata,
)
from prowler.lib.check.models import (
    Check_Metadata_Model,
    Code,
    Recommendation,
    Remediation,
    load_check_metadata,
)
from prowler.providers.aws.aws_provider import (
    get_checks_from_input_arn,
    get_regions_from_audit_resources,
)
from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"

expected_packages = [
    ModuleInfo(
        module_finder=FileFinder(
            "/root_dir/prowler/providers/azure/services/storage/storage_ensure_minimum_tls_version_12"
        ),
        name="prowler.providers.azure.services.storage.storage_ensure_minimum_tls_version_12.storage_ensure_minimum_tls_version_12",
        ispkg=False,
    ),
    ModuleInfo(
        module_finder=FileFinder("/root_dir/prowler/providers/azure/services/storage"),
        name="prowler.providers.azure.services.storage.storage_ensure_encryption_with_customer_managed_keys",
        ispkg=True,
    ),
    ModuleInfo(
        module_finder=FileFinder(
            "/root_dir/prowler/providers/azure/services/storage/storage_ensure_encryption_with_customer_managed_keys"
        ),
        name="prowler.providers.azure.services.storage.storage_ensure_encryption_with_customer_managed_keys.storage_ensure_encryption_with_customer_managed_keys",
        ispkg=False,
    ),
]

test_bulk_checks_metadata = {
    "vpc_peering_routing_tables_with_least_privilege": Check_Metadata_Model(
        Provider="aws",
        CheckID="vpc_peering_routing_tables_with_least_privilege",
        CheckTitle="Ensure routing tables for VPC peering are least access.",
        CheckType=["Infrastructure Security"],
        ServiceName="vpc",
        SubServiceName="route_table",
        ResourceIdTemplate="arn:partition:service:region:account-id:resource-id",
        Severity="medium",
        ResourceType="AwsEc2VpcPeeringConnection",
        Description="Ensure routing tables for VPC peering are least access.",
        Risk="Being highly selective in peering routing tables is a very effective way of minimizing the impact of breach as resources outside of these routes are inaccessible to the peered VPC.",
        RelatedUrl="",
        Remediation=Remediation(
            Code=Code(
                NativeIaC="",
                Terraform="",
                CLI="https://docs.bridgecrew.io/docs/networking_5#cli-command",
                Other="",
            ),
            Recommendation=Recommendation(
                Text="Review routing tables of peered VPCs for whether they route all subnets of each VPC and whether that is necessary to accomplish the intended purposes for peering the VPCs.",
                Url="https://docs.aws.amazon.com/vpc/latest/peering/peering-configurations-partial-access.html",
            ),
        ),
        Categories=["forensics-ready"],
        DependsOn=[],
        RelatedTo=[],
        Notes="",
        Compliance=None,
    ),
    "vpc_subnet_different_az": Check_Metadata_Model(
        Provider="aws",
        CheckID="vpc_subnet_different_az",
        CheckTitle="Ensure all vpc has subnets in more than one availability zone",
        CheckType=["Infrastructure Security"],
        ServiceName="vpc",
        SubServiceName="subnet",
        ResourceIdTemplate="arn:partition:service:region:account-id:resource-id",
        Severity="medium",
        ResourceType="AwsEc2Vpc",
        Description="Ensure all vpc has subnets in more than one availability zone",
        Risk="",
        RelatedUrl="https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Scenario2.html",
        Remediation=Remediation(
            Code=Code(
                NativeIaC="", Terraform="", CLI="aws ec2 create-subnet", Other=""
            ),
            Recommendation=Recommendation(
                Text="Ensure all vpc has subnets in more than one availability zone",
                Url="",
            ),
        ),
        Categories=["secrets", ""],
        DependsOn=[],
        RelatedTo=[],
        Notes="",
        Compliance=None,
    ),
    "vpc_subnet_separate_private_public": Check_Metadata_Model(
        Provider="aws",
        CheckID="vpc_subnet_separate_private_public",
        CheckTitle="Ensure all vpc has public and private subnets defined",
        CheckType=["Infrastructure Security"],
        ServiceName="vpc",
        SubServiceName="subnet",
        ResourceIdTemplate="arn:partition:service:region:account-id:resource-id",
        Severity="medium",
        ResourceType="AwsEc2Vpc",
        Description="Ensure all vpc has public and private subnets defined",
        Risk="",
        RelatedUrl="https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Scenario2.html",
        Remediation=Remediation(
            Code=Code(
                NativeIaC="", Terraform="", CLI="aws ec2 create-subnet", Other=""
            ),
            Recommendation=Recommendation(
                Text="Ensure all vpc has public and private subnets defined", Url=""
            ),
        ),
        Categories=["internet-exposed", "trustboundaries"],
        DependsOn=[],
        RelatedTo=[],
        Notes="",
        Compliance=None,
    ),
    "workspaces_volume_encryption_enabled": Check_Metadata_Model(
        Provider="aws",
        CheckID="workspaces_volume_encryption_enabled",
        CheckTitle="Ensure that your Amazon WorkSpaces storage volumes are encrypted in order to meet security and compliance requirements",
        CheckType=[],
        ServiceName="workspaces",
        SubServiceName="",
        ResourceIdTemplate="arn:aws:workspaces:region:account-id:workspace",
        Severity="high",
        ResourceType="AwsWorkspaces",
        Description="Ensure that your Amazon WorkSpaces storage volumes are encrypted in order to meet security and compliance requirements",
        Risk="If the value listed in the Volume Encryption column is Disabled the selected AWS WorkSpaces instance volumes (root and user volumes) are not encrypted. Therefore your data-at-rest is not protected from unauthorized access and does not meet the compliance requirements regarding data encryption.",
        RelatedUrl="https://docs.aws.amazon.com/workspaces/latest/adminguide/encrypt-workspaces.html",
        Remediation=Remediation(
            Code=Code(
                NativeIaC="https://docs.bridgecrew.io/docs/ensure-that-workspace-root-volumes-are-encrypted#cloudformation",
                Terraform="https://docs.bridgecrew.io/docs/ensure-that-workspace-root-volumes-are-encrypted#terraform",
                CLI="",
                Other="https://www.trendmicro.com/cloudoneconformity/knowledge-base/aws/WorkSpaces/storage-encryption.html",
            ),
            Recommendation=Recommendation(
                Text="WorkSpaces is integrated with the AWS Key Management Service (AWS KMS). This enables you to encrypt storage volumes of WorkSpaces using AWS KMS Key. When you launch a WorkSpace you can encrypt the root volume (for Microsoft Windows - the C drive; for Linux - /) and the user volume (for Windows - the D drive; for Linux - /home). Doing so ensures that the data stored at rest - disk I/O to the volume - and snapshots created from the volumes are all encrypted",
                Url="https://docs.aws.amazon.com/workspaces/latest/adminguide/encrypt-workspaces.html",
            ),
        ),
        Categories=["encryption"],
        DependsOn=[],
        RelatedTo=[],
        Notes="",
        Compliance=None,
    ),
    "workspaces_vpc_2private_1public_subnets_nat": Check_Metadata_Model(
        Provider="aws",
        CheckID="workspaces_vpc_2private_1public_subnets_nat",
        CheckTitle="Ensure that the Workspaces VPC are deployed following the best practices using 1 public subnet and 2 private subnets with a NAT Gateway attached",
        CheckType=[],
        ServiceName="workspaces",
        SubServiceName="",
        ResourceIdTemplate="arn:aws:workspaces:region:account-id:workspace",
        Severity="medium",
        ResourceType="AwsWorkspaces",
        Description="Ensure that the Workspaces VPC are deployed following the best practices using 1 public subnet and 2 private subnets with a NAT Gateway attached",
        Risk="Proper network segmentation is a key security best practice. Workspaces VPC should be deployed using 1 public subnet and 2 private subnets with a NAT Gateway attached",
        RelatedUrl="https://docs.aws.amazon.com/workspaces/latest/adminguide/amazon-workspaces-vpc.html",
        Remediation=Remediation(
            Code=Code(NativeIaC="", Terraform="", CLI="", Other=""),
            Recommendation=Recommendation(
                Text="Follow the documentation and deploy Workspaces VPC using 1 public subnet and 2 private subnets with a NAT Gateway attached",
                Url="https://docs.aws.amazon.com/workspaces/latest/adminguide/amazon-workspaces-vpc.html",
            ),
        ),
        Categories=[""],
        DependsOn=[],
        RelatedTo=[],
        Notes="",
        Compliance=None,
    ),
}


def mock_walk_packages(*_):
    return expected_packages


def mock_list_modules(*_):
    modules = [
        ModuleInfo(
            module_finder=FileFinder(
                "/root_dir/prowler/providers/azure/services/storage/storage_ensure_minimum_tls_version_12"
            ),
            name="prowler.providers.azure.services.storage.storage_ensure_minimum_tls_version_12.storage_ensure_minimum_tls_version_12",
            ispkg=False,
        ),
        ModuleInfo(
            module_finder=FileFinder(
                "/root_dir/prowler/providers/azure/services/storage"
            ),
            name="prowler.providers.azure.services.storage.storage_ensure_encryption_with_customer_managed_keys",
            ispkg=True,
        ),
        ModuleInfo(
            module_finder=FileFinder(
                "/root_dir/prowler/providers/azure/services/storage/storage_ensure_encryption_with_customer_managed_keys"
            ),
            name="prowler.providers.azure.services.storage.storage_ensure_encryption_with_customer_managed_keys.storage_ensure_encryption_with_customer_managed_keys",
            ispkg=False,
        ),
    ]
    return modules


def mock_recover_checks_from_azure_provider(*_):
    return [
        (
            "defender_ensure_defender_for_app_services_is_on",
            "/root_dir/fake_path/defender/defender_ensure_defender_for_app_services_is_on",
        ),
        (
            "iam_subscription_roles_owner_custom_not_created",
            "/root_dir/fake_path/iam/iam_subscription_roles_owner_custom_not_created",
        ),
        (
            "storage_default_network_access_rule_is_denied",
            "/root_dir/fake_path/storage/storage_default_network_access_rule_is_denied",
        ),
    ]


def mock_recover_checks_from_aws_provider(*_):
    return [
        (
            "accessanalyzer_enabled_without_findings",
            "/root_dir/fake_path/accessanalyzer/accessanalyzer_enabled_without_findings",
        ),
        (
            "awslambda_function_url_cors_policy",
            "/root_dir/fake_path/awslambda/awslambda_function_url_cors_policy",
        ),
        (
            "ec2_securitygroup_allow_ingress_from_internet_to_any_port",
            "/root_dir/fake_path/ec2/ec2_securitygroup_allow_ingress_from_internet_to_any_port",
        ),
    ]


def mock_recover_checks_from_aws_provider_lambda_service(*_):
    return [
        (
            "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
            "/root_dir/fake_path/awslambda/awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        ),
        (
            "awslambda_function_url_cors_policy",
            "/root_dir/fake_path/awslambda/awslambda_function_url_cors_policy",
        ),
        (
            "awslambda_function_no_secrets_in_code",
            "/root_dir/fake_path/awslambda/awslambda_function_no_secrets_in_code",
        ),
    ]


class Test_Check:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
        )
        return audit_info

    def test_load_check_metadata(self):
        test_cases = [
            {
                "input": {
                    "metadata_path": f"{os.path.dirname(os.path.realpath(__file__))}/fixtures/metadata.json",
                },
                "expected": {
                    "CheckID": "iam_disable_30_days_credentials",
                    "CheckTitle": "Ensure credentials unused for 30 days or greater are disabled",
                    "ServiceName": "iam",
                    "Severity": "low",
                },
            }
        ]
        for test in test_cases:
            metadata_path = test["input"]["metadata_path"]
            check_metadata = load_check_metadata(metadata_path)
            assert check_metadata.CheckID == test["expected"]["CheckID"]
            assert check_metadata.CheckTitle == test["expected"]["CheckTitle"]
            assert check_metadata.ServiceName == test["expected"]["ServiceName"]
            assert check_metadata.Severity == test["expected"]["Severity"]

    def test_parse_checks_from_file(self):
        test_cases = [
            {
                "input": {
                    "path": f"{pathlib.Path().absolute()}/tests/lib/check/fixtures/checklistA.json",
                    "provider": "aws",
                },
                "expected": {"check11", "check12", "check7777"},
            }
        ]
        for test in test_cases:
            check_file = test["input"]["path"]
            provider = test["input"]["provider"]
            assert parse_checks_from_file(check_file, provider) == test["expected"]

    @mock_s3
    def test_parse_checks_from_folder(self):
        test_checks_folder = (
            f"{pathlib.Path().absolute()}/tests/lib/check/fixtures/checks_folder"
        )
        # Create bucket and upload checks folder
        s3_client = client("s3", region_name=AWS_REGION)
        s3_client.create_bucket(Bucket="test")
        # Iterate through the files in the folder and upload each one
        for subdir, _, files in os.walk(test_checks_folder):
            for file in files:
                check = subdir.split("/")[-1]
                full_path = os.path.join(subdir, file)
                with open(full_path, "rb") as data:
                    s3_client.upload_fileobj(
                        data, "test", f"checks_folder/{check}/{file}"
                    )
        test_cases = [
            {
                "input": {
                    "path": test_checks_folder,
                    "provider": "aws",
                },
                "expected": 3,
            },
            {
                "input": {
                    "path": "s3://test/checks_folder/",
                    "provider": "aws",
                },
                "expected": 3,
            },
        ]
        for test in test_cases:
            check_folder = test["input"]["path"]
            provider = test["input"]["provider"]
            assert (
                parse_checks_from_folder(
                    self.set_mocked_audit_info(), check_folder, provider
                )
                == test["expected"]
            )
            remove_custom_checks_module(check_folder, provider)

    def test_exclude_checks_to_run(self):
        test_cases = [
            {
                "input": {
                    "check_list": {"check12", "check11", "extra72", "check13"},
                    "excluded_checks": {"check12", "check13"},
                },
                "expected": {"check11", "extra72"},
            },
            {
                "input": {
                    "check_list": {"check112", "check11", "extra72", "check13"},
                    "excluded_checks": {"check12", "check13", "check14"},
                },
                "expected": {"check112", "check11", "extra72"},
            },
        ]
        for test in test_cases:
            check_list = test["input"]["check_list"]
            excluded_checks = test["input"]["excluded_checks"]
            assert (
                exclude_checks_to_run(check_list, excluded_checks) == test["expected"]
            )

    def test_exclude_services_to_run(self):
        test_cases = [
            {
                "input": {
                    "checks_to_run": {
                        "iam_disable_30_days_credentials",
                        "iam_disable_90_days_credentials",
                    },
                    "excluded_services": {"ec2"},
                    "provider": "aws",
                },
                "expected": {
                    "iam_disable_30_days_credentials",
                    "iam_disable_90_days_credentials",
                },
            },
            {
                "input": {
                    "checks_to_run": {
                        "iam_disable_30_days_credentials",
                        "iam_disable_90_days_credentials",
                    },
                    "excluded_services": {"iam"},
                    "provider": "aws",
                },
                "expected": set(),
            },
        ]
        for test in test_cases:
            excluded_services = test["input"]["excluded_services"]
            checks_to_run = test["input"]["checks_to_run"]
            provider = test["input"]["provider"]
            assert (
                exclude_services_to_run(checks_to_run, excluded_services, provider)
                == test["expected"]
            )

    @patch(
        "prowler.lib.check.check.recover_checks_from_provider",
        new=mock_recover_checks_from_azure_provider,
    )
    def test_list_azure_services(self):
        provider = "azure"
        expected_services = {"defender", "iam", "storage"}
        listed_services = list_services(provider)
        assert listed_services == sorted(expected_services)

    @patch(
        "prowler.lib.check.check.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider,
    )
    def test_list_aws_services(self):
        provider = "azure"
        expected_services = {"accessanalyzer", "awslambda", "ec2"}
        listed_services = list_services(provider)
        assert listed_services == sorted(expected_services)

    def test_list_categories(self):
        expected_categories = {
            "secrets",
            "forensics-ready",
            "encryption",
            "internet-exposed",
            "trustboundaries",
        }
        listed_categories = list_categories(test_bulk_checks_metadata)
        assert listed_categories == expected_categories

    @patch("prowler.lib.check.check.list_modules", new=mock_list_modules)
    def test_recover_checks_from_provider(self):
        provider = "azure"
        service = "storage"
        expected_checks = [
            (
                "storage_ensure_minimum_tls_version_12",
                "/root_dir/prowler/providers/azure/services/storage/storage_ensure_minimum_tls_version_12",
            ),
            (
                "storage_ensure_encryption_with_customer_managed_keys",
                "/root_dir/prowler/providers/azure/services/storage/storage_ensure_encryption_with_customer_managed_keys",
            ),
        ]
        returned_checks = recover_checks_from_provider(provider, service)
        assert returned_checks == expected_checks

    @patch("prowler.lib.check.check.walk_packages", new=mock_walk_packages)
    def test_list_modules(self):
        provider = "azure"
        service = "storage"
        expected_modules = list_modules(provider, service)
        assert expected_modules == expected_packages

    @patch(
        "prowler.lib.check.check.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider,
    )
    def test_recover_checks_from_service(self):
        service_list = ["accessanalyzer", "awslambda", "ec2"]
        provider = "aws"
        expected_checks = {
            "accessanalyzer_enabled_without_findings",
            "awslambda_function_url_cors_policy",
            "ec2_securitygroup_allow_ingress_from_internet_to_any_port",
        }
        recovered_checks = recover_checks_from_service(service_list, provider)
        assert recovered_checks == expected_checks

    @patch(
        "prowler.lib.check.check.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider_lambda_service,
    )
    def test_get_checks_from_input_arn(self):
        audit_resources = ["arn:aws:lambda:us-east-1:123456789:function:test-lambda"]
        provider = "aws"
        expected_checks = [
            "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
            "awslambda_function_no_secrets_in_code",
            "awslambda_function_url_cors_policy",
        ]
        recovered_checks = get_checks_from_input_arn(audit_resources, provider)
        assert recovered_checks == expected_checks

    def test_get_regions_from_audit_resources(self):
        audit_resources = [
            "arn:aws:lambda:us-east-1:123456789:function:test-lambda",
            "arn:aws:iam::106908755756:policy/test",
            "arn:aws:ec2:eu-west-1:106908755756:security-group/sg-test",
        ]
        expected_regions = [
            "us-east-1",
            "eu-west-1",
        ]
        recovered_regions = get_regions_from_audit_resources(audit_resources)
        assert recovered_regions == expected_regions

    # def test_parse_checks_from_compliance_framework_two(self):
    #     test_case = {
    #         "input": {"compliance_frameworks": ["cis_v1.4_aws", "ens_v3_aws"]},
    #         "expected": {
    #             "vpc_flow_logs_enabled",
    #             "ec2_ebs_snapshot_encryption",
    #             "iam_user_mfa_enabled_console_access",
    #             "cloudtrail_multi_region_enabled",
    #             "ec2_elbv2_insecure_ssl_ciphers",
    #             "guardduty_is_enabled",
    #             "s3_bucket_default_encryption",
    #             "cloudfront_distributions_https_enabled",
    #             "iam_avoid_root_usage",
    #             "s3_bucket_secure_transport_policy",
    #         },
    #     }
    #     with mock.patch(
    #         "prowler.lib.check.check.compliance_specification_dir_path",
    #         new=f"{pathlib.Path().absolute()}/fixtures",
    #     ):
    #         provider = "aws"
    #         bulk_compliance_frameworks = bulk_load_compliance_frameworks(provider)
    #         compliance_frameworks = test_case["input"]["compliance_frameworks"]
    #         assert (
    #             parse_checks_from_compliance_framework(
    #                 compliance_frameworks, bulk_compliance_frameworks
    #             )
    #             == test_case["expected"]
    #         )

    # def test_parse_checks_from_compliance_framework_one(self):
    #     test_case = {
    #         "input": {"compliance_frameworks": ["cis_v1.4_aws"]},
    #         "expected": {
    #             "iam_user_mfa_enabled_console_access",
    #             "s3_bucket_default_encryption",
    #             "iam_avoid_root_usage",
    #         },
    #     }
    #     with mock.patch(
    #         "prowler.lib.check.check.compliance_specification_dir",
    #         new=f"{pathlib.Path().absolute()}/fixtures",
    #     ):
    #         provider = "aws"
    #         bulk_compliance_frameworks = bulk_load_compliance_frameworks(provider)
    #         compliance_frameworks = test_case["input"]["compliance_frameworks"]
    #         assert (
    #             parse_checks_from_compliance_framework(
    #                 compliance_frameworks, bulk_compliance_frameworks
    #             )
    #             == test_case["expected"]
    #         )

    # def test_parse_checks_from_compliance_framework_no_compliance(self):
    #     test_case = {
    #         "input": {"compliance_frameworks": []},
    #         "expected": set(),
    #     }
    #     with mock.patch(
    #         "prowler.lib.check.check.compliance_specification_dir",
    #         new=f"{pathlib.Path().absolute()}/fixtures",
    #     ):
    #         provider = "aws"
    #         bulk_compliance_frameworks = bulk_load_compliance_frameworks(provider)
    #         compliance_frameworks = test_case["input"]["compliance_frameworks"]
    #         assert (
    #             parse_checks_from_compliance_framework(
    #                 compliance_frameworks, bulk_compliance_frameworks
    #             )
    #             == test_case["expected"]
    #         )

    def test_update_audit_metadata_complete(self):
        from prowler.providers.common.models import Audit_Metadata

        # Set the expected checks to run
        expected_checks = ["iam_administrator_access_with_mfa"]
        services_executed = {"iam"}
        checks_executed = {"iam_administrator_access_with_mfa"}

        # Set an empty Audit_Metadata
        audit_metadata = Audit_Metadata(
            services_scanned=0,
            expected_checks=expected_checks,
            completed_checks=0,
            audit_progress=0,
        )

        audit_metadata = update_audit_metadata(
            audit_metadata, services_executed, checks_executed
        )

        assert audit_metadata.audit_progress == float(100)
        assert audit_metadata.services_scanned == 1
        assert audit_metadata.expected_checks == expected_checks
        assert audit_metadata.completed_checks == 1

    def test_update_audit_metadata_50(self):
        from prowler.providers.common.models import Audit_Metadata

        # Set the expected checks to run
        expected_checks = [
            "iam_administrator_access_with_mfa",
            "iam_support_role_created",
        ]
        services_executed = {"iam"}
        checks_executed = {"iam_administrator_access_with_mfa"}

        # Set an empty Audit_Metadata
        audit_metadata = Audit_Metadata(
            services_scanned=0,
            expected_checks=expected_checks,
            completed_checks=0,
            audit_progress=0,
        )

        audit_metadata = update_audit_metadata(
            audit_metadata, services_executed, checks_executed
        )

        assert audit_metadata.audit_progress == float(50)
        assert audit_metadata.services_scanned == 1
        assert audit_metadata.expected_checks == expected_checks
        assert audit_metadata.completed_checks == 1
