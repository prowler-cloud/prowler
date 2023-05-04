from datetime import datetime
from unittest.mock import patch

import botocore
from boto3 import client, session
from moto import mock_ecr

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.ecr.ecr_service import ECR, ScanningRule

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "eu-west-1"

repo_arn = f"arn:aws:ecr:eu-west-1:{AWS_ACCOUNT_NUMBER}:repository/test-repo"
repo_name = "test-repo"

# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeImages":
        return {
            "imageDetails": [
                {
                    "imageDigest": "sha256:d8868e50ac4c7104d2200d42f432b661b2da8c1e417ccfae217e6a1e04bb9295",
                    "imageTags": [
                        "test-tag1",
                    ],
                    "imagePushedAt": datetime(2023, 1, 1),
                    "imageScanStatus": {
                        "status": "COMPLETE",
                    },
                    "imageScanFindingsSummary": {
                        "findingSeverityCounts": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3}
                    },
                },
                {
                    "imageDigest": "sha256:83251ac64627fc331584f6c498b3aba5badc01574e2c70b2499af3af16630eed",
                    "imageTags": [
                        "test-tag2",
                    ],
                    "imagePushedAt": datetime(2023, 1, 2),
                    "imageScanStatus": {
                        "status": "COMPLETE",
                    },
                    "imageScanFindingsSummary": {
                        "findingSeverityCounts": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3}
                    },
                },
            ],
        }
    if operation_name == "GetRepositoryPolicy":
        return {
            "registryId": "string",
            "repositoryName": "string",
            "policyText": '{\n  "Version" : "2012-10-17",\n  "Statement" : [ {\n    "Sid" : "Allow Describe Images",\n    "Effect" : "Allow",\n    "Principal" : {\n      "AWS" : [ "arn:aws:iam::123456789012:root" ]\n    },\n    "Action" : [ "ecr:DescribeImages", "ecr:DescribeRepositories" ]\n  } ]\n}',
        }
    if operation_name == "GetLifecyclePolicy":
        return {
            "registryId": "string",
            "repositoryName": "string",
            "lifecyclePolicyText": "test-policy",
        }
    if operation_name == "GetRegistryScanningConfiguration":
        return {
            "registryId": AWS_ACCOUNT_NUMBER,
            "scanningConfiguration": {
                "scanType": "BASIC",
                "rules": [
                    {
                        "scanFrequency": "SCAN_ON_PUSH",
                        "repositoryFilters": [
                            {"filter": "*", "filterType": "WILDCARD"},
                        ],
                    },
                ],
            },
        }

    return make_api_call(self, operation_name, kwarg)


def mock_generate_regional_clients(service, audit_info):
    regional_client = audit_info.audit_session.client(service, region_name=AWS_REGION)
    regional_client.region = AWS_REGION
    return {AWS_REGION: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.services.ecr.ecr_service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_ECR_Service:
    # Mocked Audit Info
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

    # Test ECR Service
    def test_service(self):
        audit_info = self.set_mocked_audit_info()
        ecr = ECR(audit_info)
        assert ecr.service == "ecr"

    # Test ECR client
    def test_client(self):
        audit_info = self.set_mocked_audit_info()
        ecr = ECR(audit_info)
        for regional_client in ecr.regional_clients.values():
            assert regional_client.__class__.__name__ == "ECR"

    # Test ECR session
    def test__get_session__(self):
        audit_info = self.set_mocked_audit_info()
        ecr = ECR(audit_info)
        assert ecr.session.__class__.__name__ == "Session"

    # Test describe ECR repositories
    @mock_ecr
    def test__describe_registries_and_repositories__(self):
        ecr_client = client("ecr", region_name=AWS_REGION)
        ecr_client.create_repository(
            repositoryName=repo_name,
            imageScanningConfiguration={"scanOnPush": True},
            tags=[
                {"Key": "test", "Value": "test"},
            ],
        )
        audit_info = self.set_mocked_audit_info()
        ecr = ECR(audit_info)

        assert len(ecr.registries) == 1
        assert ecr.registries[AWS_REGION].id == AWS_ACCOUNT_NUMBER
        assert ecr.registries[AWS_REGION].region == AWS_REGION
        assert len(ecr.registries[AWS_REGION].repositories) == 1

        assert ecr.registries[AWS_REGION].repositories[0].name == repo_name
        assert ecr.registries[AWS_REGION].repositories[0].arn == repo_arn
        assert ecr.registries[AWS_REGION].repositories[0].scan_on_push
        assert ecr.registries[AWS_REGION].repositories[0].tags == [
            {"Key": "test", "Value": "test"},
        ]

    # Test describe ECR repository policies
    @mock_ecr
    def test__describe_repository_policies__(self):
        ecr_client = client("ecr", region_name=AWS_REGION)
        ecr_client.create_repository(
            repositoryName=repo_name,
            imageScanningConfiguration={"scanOnPush": True},
        )
        audit_info = self.set_mocked_audit_info()
        ecr = ECR(audit_info)
        assert len(ecr.registries) == 1
        assert len(ecr.registries[AWS_REGION].repositories) == 1
        assert ecr.registries[AWS_REGION].repositories[0].name == repo_name
        assert ecr.registries[AWS_REGION].repositories[0].arn == repo_arn
        assert ecr.registries[AWS_REGION].repositories[0].scan_on_push
        assert (
            ecr.registries[AWS_REGION].repositories[0].policy["Statement"][0]["Sid"]
            == "Allow Describe Images"
        )
        assert (
            ecr.registries[AWS_REGION].repositories[0].policy["Statement"][0]["Effect"]
            == "Allow"
        )
        assert (
            ecr.registries[AWS_REGION]
            .repositories[0]
            .policy["Statement"][0]["Principal"]["AWS"][0]
            == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        assert (
            ecr.registries[AWS_REGION]
            .repositories[0]
            .policy["Statement"][0]["Action"][0]
            == "ecr:DescribeImages"
        )
        assert (
            ecr.registries[AWS_REGION]
            .repositories[0]
            .policy["Statement"][0]["Action"][1]
            == "ecr:DescribeRepositories"
        )

    # Test describe ECR repository lifecycle policies
    @mock_ecr
    def test__get_lifecycle_policies__(self):
        ecr_client = client("ecr", region_name=AWS_REGION)
        ecr_client.create_repository(
            repositoryName=repo_name,
            imageScanningConfiguration={"scanOnPush": True},
        )
        audit_info = self.set_mocked_audit_info()
        ecr = ECR(audit_info)
        assert len(ecr.registries) == 1
        assert len(ecr.registries[AWS_REGION].repositories) == 1
        assert ecr.registries[AWS_REGION].repositories[0].name == repo_name
        assert ecr.registries[AWS_REGION].repositories[0].arn == repo_arn
        assert ecr.registries[AWS_REGION].repositories[0].scan_on_push
        assert ecr.registries[AWS_REGION].repositories[0].lifecycle_policy

    # Test get image details
    @mock_ecr
    def test__get_image_details__(self):
        ecr_client = client("ecr", region_name=AWS_REGION)
        ecr_client.create_repository(
            repositoryName=repo_name,
            imageScanningConfiguration={"scanOnPush": True},
        )
        audit_info = self.set_mocked_audit_info()
        ecr = ECR(audit_info)
        assert len(ecr.registries) == 1
        assert len(ecr.registries[AWS_REGION].repositories) == 1
        assert ecr.registries[AWS_REGION].repositories[0].name == repo_name
        assert ecr.registries[AWS_REGION].repositories[0].arn == repo_arn
        assert ecr.registries[AWS_REGION].repositories[0].scan_on_push
        assert len(ecr.registries[AWS_REGION].repositories[0].images_details) == 2
        # First image pushed
        assert ecr.registries[AWS_REGION].repositories[0].images_details[
            0
        ].image_pushed_at == datetime(2023, 1, 1)
        assert (
            ecr.registries[AWS_REGION].repositories[0].images_details[0].latest_tag
            == "test-tag1"
        )
        assert (
            ecr.registries[AWS_REGION].repositories[0].images_details[0].latest_digest
            == "sha256:d8868e50ac4c7104d2200d42f432b661b2da8c1e417ccfae217e6a1e04bb9295"
        )
        assert (
            ecr.registries[AWS_REGION]
            .repositories[0]
            .images_details[0]
            .scan_findings_status
            == "COMPLETE"
        )
        assert (
            ecr.registries[AWS_REGION]
            .repositories[0]
            .images_details[0]
            .scan_findings_severity_count.critical
            == 1
        )
        assert (
            ecr.registries[AWS_REGION]
            .repositories[0]
            .images_details[0]
            .scan_findings_severity_count.high
            == 2
        )
        assert (
            ecr.registries[AWS_REGION]
            .repositories[0]
            .images_details[0]
            .scan_findings_severity_count.medium
            == 3
        )

        # Second image pushed
        assert ecr.registries[AWS_REGION].repositories[0].images_details[
            1
        ].image_pushed_at == datetime(2023, 1, 2)
        assert (
            ecr.registries[AWS_REGION].repositories[0].images_details[1].latest_tag
            == "test-tag2"
        )
        assert (
            ecr.registries[AWS_REGION].repositories[0].images_details[1].latest_digest
            == "sha256:83251ac64627fc331584f6c498b3aba5badc01574e2c70b2499af3af16630eed"
        )
        assert (
            ecr.registries[AWS_REGION]
            .repositories[0]
            .images_details[1]
            .scan_findings_status
            == "COMPLETE"
        )
        assert (
            ecr.registries[AWS_REGION]
            .repositories[0]
            .images_details[1]
            .scan_findings_severity_count.critical
            == 1
        )
        assert (
            ecr.registries[AWS_REGION]
            .repositories[0]
            .images_details[1]
            .scan_findings_severity_count.high
            == 2
        )
        assert (
            ecr.registries[AWS_REGION]
            .repositories[0]
            .images_details[1]
            .scan_findings_severity_count.medium
            == 3
        )

    # Test get ECR Registries Scanning Configuration
    @mock_ecr
    def test__get_registry_scanning_configuration__(self):
        audit_info = self.set_mocked_audit_info()
        ecr = ECR(audit_info)
        assert len(ecr.registries) == 1
        assert ecr.registries[AWS_REGION].id == AWS_ACCOUNT_NUMBER
        assert ecr.registries[AWS_REGION].scan_type == "BASIC"
        assert ecr.registries[AWS_REGION].rules == [
            ScanningRule(
                scan_frequency="SCAN_ON_PUSH",
                scan_filters=[{"filter": "*", "filterType": "WILDCARD"}],
            )
        ]
