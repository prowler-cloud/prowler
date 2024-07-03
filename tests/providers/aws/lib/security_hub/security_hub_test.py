from datetime import datetime
from logging import ERROR, WARNING

import botocore
from boto3 import session
from botocore.client import ClientError
from mock import patch

from prowler.lib.outputs.asff.asff import ASFF
from prowler.lib.outputs.finding import Finding, Severity, Status
from prowler.providers.aws.lib.security_hub.security_hub import (
    batch_send_to_security_hub,
    filter_security_hub_findings_per_region,
    verify_security_hub_integration_enabled_per_region,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_COMMERCIAL_PARTITION,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_EU_WEST_2,
)

# Mocking Security Hub Get Findings
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "BatchImportFindings":
        return {
            "FailedCount": 0,
            "SuccessCount": 1,
        }
    if operation_name == "DescribeHub":
        return {
            "HubArn": f"arn:aws:securityhub:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:hub/default",
            "SubscribedAt": "2023-02-07T09:45:43.742Z",
            "AutoEnableControls": True,
            "ControlFindingGenerator": "STANDARD_CONTROL",
        }

    if operation_name == "ListEnabledProductsForImport":
        return {
            "ProductSubscriptions": [
                f"arn:aws:securityhub:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:product-subscription/prowler/prowler",
            ]
        }

    return make_api_call(self, operation_name, kwarg)


def set_mocked_session(region):
    # Create mock session
    return session.Session(
        region_name=region,
    )


def generate_finding(status: str, region: str, muted: bool = False) -> Finding:
    return Finding(
        auth_method="",
        timestamp=datetime.now(),
        account_uid="12345",
        account_name="Example Account",
        account_email="example@example.com",
        account_organization_uid="org-123",
        account_organization_name="Example Org",
        account_tags=["tag1", "tag2"],
        finding_uid="finding-123",
        provider="aws",
        check_id="check-123",
        check_title="Example Check",
        check_type="Security",
        status=Status(status),
        status_extended="Extended status",
        muted=muted,
        service_name="Example Service",
        subservice_name="Example Subservice",
        severity=Severity("critical"),
        resource_type="Instance",
        resource_uid="resource-123",
        resource_name="Example Resource",
        resource_details="Detailed information about the resource",
        resource_tags="tag1 | tag2",
        partition="aws",
        region=region,
        description="Description of the finding",
        risk="High",
        related_url="http://example.com",
        remediation_recommendation_text="Recommendation text",
        remediation_recommendation_url="http://example.com/remediation",
        remediation_code_nativeiac="native-iac-code",
        remediation_code_terraform="terraform-code",
        remediation_code_cli="cli-code",
        remediation_code_other="other-code",
        compliance={"compliance_key": "compliance_value"},
        categories="category1,category2",
        depends_on="dependency",
        related_to="related finding",
        notes="Notes about the finding",
        prowler_version="1.0",
    )


class TestSecurityHub:

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_verify_security_hub_integration_enabled_per_region(self):
        session = set_mocked_session(AWS_REGION_EU_WEST_1)
        assert verify_security_hub_integration_enabled_per_region(
            AWS_COMMERCIAL_PARTITION, AWS_REGION_EU_WEST_1, session, AWS_ACCOUNT_NUMBER
        )

    def test_verify_security_hub_integration_enabled_per_region_security_hub_disabled(
        self, caplog
    ):
        caplog.set_level(WARNING)
        session = set_mocked_session(AWS_REGION_EU_WEST_1)

        with patch(
            "prowler.providers.aws.lib.security_hub.security_hub.session.Session.client",
        ) as mock_security_hub:
            error_message = f"Account {AWS_ACCOUNT_NUMBER} is not subscribed to AWS Security Hub in region {AWS_REGION_EU_WEST_1}"
            error_code = "InvalidAccessException"
            error_response = {
                "Error": {
                    "Code": error_code,
                    "Message": error_message,
                }
            }
            operation_name = "DescribeHub"
            mock_security_hub.side_effect = ClientError(error_response, operation_name)

            assert not verify_security_hub_integration_enabled_per_region(
                AWS_COMMERCIAL_PARTITION,
                AWS_REGION_EU_WEST_1,
                session,
                AWS_ACCOUNT_NUMBER,
            )
            assert caplog.record_tuples == [
                (
                    "root",
                    WARNING,
                    f"ClientError -- [68]: An error occurred ({error_code}) when calling the {operation_name} operation: {error_message}",
                )
            ]

    def test_verify_security_hub_integration_enabled_per_region_prowler_not_subscribed(
        self, caplog
    ):
        caplog.set_level(WARNING)
        session = set_mocked_session(AWS_REGION_EU_WEST_1)

        with patch(
            "prowler.providers.aws.lib.security_hub.security_hub.session.Session.client",
        ) as mock_security_hub:
            mock_security_hub.describe_hub.return_value = None
            mock_security_hub.list_enabled_products_for_import.return_value = []

            assert not verify_security_hub_integration_enabled_per_region(
                AWS_COMMERCIAL_PARTITION,
                AWS_REGION_EU_WEST_1,
                session,
                AWS_ACCOUNT_NUMBER,
            )
            assert caplog.record_tuples == [
                (
                    "root",
                    WARNING,
                    f"Security Hub is enabled in {AWS_REGION_EU_WEST_1} but Prowler integration does not accept findings. More info: https://docs.prowler.cloud/en/latest/tutorials/aws/securityhub/",
                )
            ]

    def test_verify_security_hub_integration_enabled_per_region_another_ClientError(
        self, caplog
    ):
        caplog.set_level(WARNING)
        session = set_mocked_session(AWS_REGION_EU_WEST_1)

        with patch(
            "prowler.providers.aws.lib.security_hub.security_hub.session.Session.client",
        ) as mock_security_hub:
            error_message = f"Another exception in region {AWS_REGION_EU_WEST_1}"
            error_code = "AnotherException"
            error_response = {
                "Error": {
                    "Code": error_code,
                    "Message": error_message,
                }
            }
            operation_name = "DescribeHub"
            mock_security_hub.side_effect = ClientError(error_response, operation_name)

            assert not verify_security_hub_integration_enabled_per_region(
                AWS_COMMERCIAL_PARTITION,
                AWS_REGION_EU_WEST_1,
                session,
                AWS_ACCOUNT_NUMBER,
            )
            assert caplog.record_tuples == [
                (
                    "root",
                    ERROR,
                    f"ClientError -- [68]: An error occurred ({error_code}) when calling the {operation_name} operation: {error_message}",
                )
            ]

    def test_verify_security_hub_integration_enabled_per_region_another_Exception(
        self, caplog
    ):
        caplog.set_level(WARNING)
        session = set_mocked_session(AWS_REGION_EU_WEST_1)

        with patch(
            "prowler.providers.aws.lib.security_hub.security_hub.session.Session.client",
        ) as mock_security_hub:
            error_message = f"Another exception in region {AWS_REGION_EU_WEST_1}"
            mock_security_hub.side_effect = Exception(error_message)

            assert not verify_security_hub_integration_enabled_per_region(
                AWS_COMMERCIAL_PARTITION,
                AWS_REGION_EU_WEST_1,
                session,
                AWS_ACCOUNT_NUMBER,
            )
            assert caplog.record_tuples == [
                (
                    "root",
                    ERROR,
                    f"Exception -- [68]: {error_message}",
                )
            ]

    def test_filter_security_hub_findings_per_region_enabled_region_all_statuses(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        findings = [generate_finding("PASS", AWS_REGION_EU_WEST_1)]
        asff = ASFF(findings=findings)
        asff_finding = asff.data[0]

        assert filter_security_hub_findings_per_region(
            asff.data,
            False,
            [],
            enabled_regions,
        ) == {
            AWS_REGION_EU_WEST_1: [asff_finding],
        }

    def test_filter_security_hub_findings_per_region_all_statuses_MANUAL_finding(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        findings = [generate_finding("MANUAL", AWS_REGION_EU_WEST_1)]
        asff = ASFF(findings=findings)

        assert filter_security_hub_findings_per_region(
            asff.data,
            False,
            [],
            enabled_regions,
        ) == {AWS_REGION_EU_WEST_1: []}

    def test_filter_security_hub_findings_per_region_disabled_region(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        findings = [generate_finding("PASS", AWS_REGION_EU_WEST_2)]
        asff = ASFF(findings=findings)

        assert filter_security_hub_findings_per_region(
            asff.data,
            False,
            [],
            enabled_regions,
        ) == {AWS_REGION_EU_WEST_1: []}

    def test_filter_security_hub_findings_per_region_PASS_and_FAIL_statuses(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        findings = [generate_finding("PASS", AWS_REGION_EU_WEST_1)]
        asff = ASFF(findings=findings)

        assert filter_security_hub_findings_per_region(
            asff.data,
            False,
            ["FAIL"],
            enabled_regions,
        ) == {AWS_REGION_EU_WEST_1: []}

    def test_filter_security_hub_findings_per_region_FAIL_and_FAIL_statuses(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        findings = [generate_finding("FAIL", AWS_REGION_EU_WEST_1)]
        asff = ASFF(findings=findings)

        assert filter_security_hub_findings_per_region(
            asff.data,
            False,
            ["FAIL"],
            enabled_regions,
        ) == {AWS_REGION_EU_WEST_1: [asff.data[0]]}

    def test_filter_security_hub_findings_per_region_send_sh_only_fails_PASS(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        findings = [generate_finding("PASS", AWS_REGION_EU_WEST_1)]
        asff = ASFF(findings=findings)

        assert filter_security_hub_findings_per_region(
            asff.data,
            True,
            [],
            enabled_regions,
        ) == {AWS_REGION_EU_WEST_1: []}

    def test_filter_security_hub_findings_per_region_send_sh_only_fails_FAIL(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        findings = [generate_finding("FAIL", AWS_REGION_EU_WEST_1)]
        asff = ASFF(findings=findings)

        assert filter_security_hub_findings_per_region(
            asff.data,
            True,
            [],
            enabled_regions,
        ) == {AWS_REGION_EU_WEST_1: [asff.data[0]]}

    def test_filter_security_hub_findings_per_region_no_audited_regions(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        findings = [generate_finding("PASS", AWS_REGION_EU_WEST_1)]
        asff = ASFF(findings=findings)

        assert filter_security_hub_findings_per_region(
            asff.data,
            False,
            [],
            enabled_regions,
        ) == {
            AWS_REGION_EU_WEST_1: [asff.data[0]],
        }

    def test_filter_security_hub_findings_per_region_muted_fail_with_send_sh_only_fails(
        self,
    ):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        findings = [
            generate_finding(status="FAIL", region=AWS_REGION_EU_WEST_1, muted=True)
        ]
        asff = ASFF(findings=findings)

        assert filter_security_hub_findings_per_region(
            asff.data,
            True,
            [],
            enabled_regions,
        ) == {
            AWS_REGION_EU_WEST_1: [],
        }

    def test_filter_security_hub_findings_per_region_muted_fail_with_status_FAIL(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        findings = [
            generate_finding(status="FAIL", region=AWS_REGION_EU_WEST_1, muted=True)
        ]
        asff = ASFF(findings=findings)

        assert filter_security_hub_findings_per_region(
            asff.data,
            False,
            ["FAIL"],
            enabled_regions,
        ) == {
            AWS_REGION_EU_WEST_1: [],
        }

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_batch_send_to_security_hub_one_finding(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        findings = [generate_finding("PASS", AWS_REGION_EU_WEST_1)]
        asff = ASFF(findings=findings)
        session = set_mocked_session(AWS_REGION_EU_WEST_1)

        security_hub_findings = filter_security_hub_findings_per_region(
            asff.data,
            False,
            [],
            enabled_regions,
        )

        assert (
            batch_send_to_security_hub(
                security_hub_findings,
                session,
            )
            == 1
        )
