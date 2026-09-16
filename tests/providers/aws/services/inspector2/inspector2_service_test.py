from datetime import datetime, timezone
from unittest.mock import patch

import botocore
from botocore.exceptions import ClientError

from prowler.providers.aws.services.inspector2.inspector2_service import (
    Finding,
    Inspector,
    Inspector2,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

FINDING_ARN = (
    "arn:aws:inspector2:us-east-1:123456789012:finding/0e436649379db5f327e3cf5bb4421d76"
)
VULNERABILITY_ID = "CVE-2022-40897"
INSTANCE_ID = "i-0123456789abcdef0"
FIRST_OBSERVED_AT = datetime(2024, 1, 1, tzinfo=timezone.utc)
LAST_SCANNED_AT = datetime(2024, 6, 1, tzinfo=timezone.utc)
KEV_DATE_ADDED = datetime(2024, 4, 12, tzinfo=timezone.utc)
KEV_DATE_DUE = datetime(2024, 5, 3, tzinfo=timezone.utc)

# Mocking Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwargs):
    """We have to mock every AWS API call using Boto3"""
    if operation_name == "BatchGetAccountStatus":
        return {
            "accounts": [
                {
                    "accountId": AWS_ACCOUNT_NUMBER,
                    "resourceState": {
                        "ec2": {
                            "errorCode": "ALREADY_ENABLED",
                            "errorMessage": "string",
                            "status": "ENABLED",
                        },
                        "ecr": {
                            "errorCode": "ALREADY_ENABLED",
                            "errorMessage": "string",
                            "status": "ENABLED",
                        },
                        "lambda": {
                            "errorCode": "ALREADY_ENABLED",
                            "errorMessage": "string",
                            "status": "ENABLED",
                        },
                        "lambdaCode": {
                            "errorCode": "ALREADY_ENABLED",
                            "errorMessage": "string",
                            "status": "ENABLED",
                        },
                    },
                    "state": {
                        "errorCode": "ALREADY_ENABLED",
                        "errorMessage": "string",
                        "status": "ENABLED",
                    },
                }
            ]
        }
    if operation_name == "ListFindings":
        return {
            "findings": [
                {
                    "awsAccountId": AWS_ACCOUNT_NUMBER,
                    "findingArn": FINDING_ARN,
                    "description": "Finding Description",
                    "severity": "MEDIUM",
                    "status": "ACTIVE",
                    "title": f"{VULNERABILITY_ID} - setuptools",
                    "type": "PACKAGE_VULNERABILITY",
                    "firstObservedAt": FIRST_OBSERVED_AT,
                    "updatedAt": datetime(2024, 1, 1),
                    "packageVulnerabilityDetails": {
                        "vulnerabilityId": VULNERABILITY_ID
                    },
                    "resources": [{"id": INSTANCE_ID, "type": "AWS_EC2_INSTANCE"}],
                }
            ]
        }
    if operation_name == "ListCoverage":
        return {
            "coveredResources": [
                {
                    "resourceId": INSTANCE_ID,
                    "resourceType": "AWS_EC2_INSTANCE",
                    "accountId": AWS_ACCOUNT_NUMBER,
                    "scanType": "PACKAGE",
                    "scanStatus": {"statusCode": "ACTIVE", "reason": "SUCCESSFUL"},
                    "lastScannedAt": LAST_SCANNED_AT,
                }
            ]
        }
    if operation_name == "BatchGetFindingDetails":
        return {
            "findingDetails": [
                {
                    "findingArn": FINDING_ARN,
                    "cisaData": {
                        "dateAdded": KEV_DATE_ADDED,
                        "dateDue": KEV_DATE_DUE,
                    },
                }
            ],
            "errors": [],
        }

    return make_api_call(self, operation_name, kwargs)


def mock_make_api_call_finding_details_denied(self, operation_name, kwargs):
    if operation_name == "BatchGetFindingDetails":
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            operation_name,
        )
    return mock_make_api_call(self, operation_name, kwargs)


def mock_finding_details_error(error_code):
    def _mock(self, operation_name, kwargs):
        if operation_name == "BatchGetFindingDetails":
            return {
                "findingDetails": [],
                "errors": [
                    {
                        "findingArn": FINDING_ARN,
                        "errorCode": error_code,
                        "errorMessage": "error",
                    }
                ],
            }
        return mock_make_api_call(self, operation_name, kwargs)

    return _mock


def mock_make_api_call_list_denied(self, operation_name, kwargs):
    if operation_name in ("ListFindings", "ListCoverage"):
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            operation_name,
        )
    return mock_make_api_call(self, operation_name, kwargs)


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


def build_inspector(region, vulnerability_ids):
    return Inspector(
        id="Inspector2",
        arn=f"arn:aws:inspector2:{region}:{AWS_ACCOUNT_NUMBER}:inspector2",
        region=region,
        status="ENABLED",
        ec2_status="ENABLED",
        ecr_status="ENABLED",
        lambda_status="ENABLED",
        lambda_code_status="ENABLED",
        findings=[
            Finding(
                arn=f"arn:aws:inspector2:{region}:{AWS_ACCOUNT_NUMBER}:finding/{index}",
                type="PACKAGE_VULNERABILITY",
                severity="HIGH",
                first_observed_at=FIRST_OBSERVED_AT,
                vulnerability_id=vulnerability_id,
            )
            for index, vulnerability_id in enumerate(vulnerability_ids)
        ],
    )


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_Inspector2_Service:
    def test_get_client(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2 = Inspector2(aws_provider)
        assert (
            inspector2.regional_clients[AWS_REGION_EU_WEST_1].__class__.__name__
            == "Inspector2"
        )

    def test__get_service__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2 = Inspector2(aws_provider)
        assert inspector2.service == "inspector2"

    def test_batch_get_account_status(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2 = Inspector2(aws_provider)
        assert len(inspector2.inspectors) == 1
        assert inspector2.inspectors[0].id == "Inspector2"
        assert inspector2.inspectors[0].region == AWS_REGION_EU_WEST_1
        assert inspector2.inspectors[0].status == "ENABLED"
        assert inspector2.inspectors[0].ec2_status == "ENABLED"
        assert inspector2.inspectors[0].ecr_status == "ENABLED"
        assert inspector2.inspectors[0].lambda_status == "ENABLED"
        assert inspector2.inspectors[0].lambda_code_status == "ENABLED"

    def test_list_active_findings(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2 = Inspector2(aws_provider)
        assert inspector2.inspectors[0].active_findings

    def test_list_findings(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2 = Inspector2(aws_provider)
        findings = inspector2.inspectors[0].findings
        assert len(findings) == 1
        assert findings[0].arn == FINDING_ARN
        assert findings[0].type == "PACKAGE_VULNERABILITY"
        assert findings[0].severity == "MEDIUM"
        assert findings[0].first_observed_at == FIRST_OBSERVED_AT
        assert findings[0].vulnerability_id == VULNERABILITY_ID
        assert findings[0].resource_ids == [INSTANCE_ID]

    def test_list_coverage(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2 = Inspector2(aws_provider)
        coverage = inspector2.inspectors[0].coverage
        assert len(coverage) == 1
        assert coverage[0].id == INSTANCE_ID
        assert (
            coverage[0].arn
            == f"arn:aws:ec2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:instance/{INSTANCE_ID}"
        )
        assert coverage[0].region == AWS_REGION_EU_WEST_1
        assert coverage[0].resource_type == "AWS_EC2_INSTANCE"
        assert coverage[0].scan_type == "PACKAGE"
        assert coverage[0].scan_status_code == "ACTIVE"
        assert coverage[0].scan_status_reason == "SUCCESSFUL"
        assert coverage[0].last_scanned_at == LAST_SCANNED_AT

    def test_list_coverage_keeps_audited_resources(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        aws_provider._audit_resources = [
            f"arn:aws:ec2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:instance/{INSTANCE_ID}"
        ]
        inspector2 = Inspector2(aws_provider)
        assert len(inspector2.inspectors[0].coverage) == 1

    def test_list_coverage_skips_non_audited_resources(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        aws_provider._audit_resources = [
            f"arn:aws:ec2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:instance/i-0fedcba9876543210"
        ]
        inspector2 = Inspector2(aws_provider)
        assert inspector2.inspectors[0].coverage == []

    def test_batch_get_finding_details(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2 = Inspector2(aws_provider)
        known_exploited = inspector2.known_exploited_vulnerabilities[VULNERABILITY_ID]
        assert known_exploited.id == VULNERABILITY_ID
        assert known_exploited.date_added == KEV_DATE_ADDED
        assert known_exploited.date_due == KEV_DATE_DUE
        assert inspector2.vulnerability_lookup_failed == set()

    def test_batch_get_finding_details_denied(self):
        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_finding_details_denied,
        ):
            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            inspector2 = Inspector2(aws_provider)
        assert inspector2.known_exploited_vulnerabilities == {}
        assert inspector2.vulnerability_lookup_failed == {VULNERABILITY_ID}

    def test_finding_details_not_found_is_not_a_lookup_failure(self):
        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_finding_details_error("FINDING_DETAILS_NOT_FOUND"),
        ):
            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            inspector2 = Inspector2(aws_provider)
        assert inspector2.known_exploited_vulnerabilities == {}
        assert inspector2.vulnerability_lookup_failed == set()

    def test_finding_details_error_is_a_lookup_failure(self):
        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_finding_details_error("INTERNAL_ERROR"),
        ):
            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            inspector2 = Inspector2(aws_provider)
        assert inspector2.known_exploited_vulnerabilities == {}
        assert inspector2.vulnerability_lookup_failed == {VULNERABILITY_ID}

    def test_list_findings_and_coverage_denied(self):
        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_list_denied,
        ):
            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
            inspector2 = Inspector2(aws_provider)
        assert inspector2.inspectors[0].findings is None
        assert inspector2.inspectors[0].coverage is None
        assert inspector2.known_exploited_vulnerabilities == {}

    def test_finding_detail_batches_use_one_finding_per_cve(self):
        vulnerability_ids = [f"CVE-2024-{number:04d}" for number in range(25)]
        batches = Inspector2._get_finding_detail_batches(
            [
                build_inspector(
                    AWS_REGION_EU_WEST_1,
                    vulnerability_ids + vulnerability_ids[:5] + ["GHSA-xxxx-yyyy-zzzz"],
                ),
                build_inspector(AWS_REGION_US_EAST_1, vulnerability_ids[:3]),
            ]
        )
        assert [region for region, _ in batches] == [AWS_REGION_EU_WEST_1] * 3
        assert [len(findings) for _, findings in batches] == [10, 10, 5]
        assert sorted(cve for _, findings in batches for _, cve in findings) == sorted(
            vulnerability_ids
        )
