from logging import ERROR, WARNING
from os import path

import botocore
from boto3 import session
from botocore.client import ClientError
from mock import MagicMock, patch

from prowler.config.config import prowler_version, timestamp_utc
from prowler.lib.check.models import Check_Report, load_check_metadata
from prowler.providers.aws.lib.security_hub.security_hub import (
    batch_send_to_security_hub,
    prepare_security_hub_findings,
    verify_security_hub_integration_enabled_per_region,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_COMMERCIAL_PARTITION,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_EU_WEST_2,
    set_mocked_aws_provider,
)


def get_security_hub_finding(status: str):
    return {
        "SchemaVersion": "2018-10-08",
        "Id": f"prowler-iam_user_accesskey_unused-{AWS_ACCOUNT_NUMBER}-{AWS_REGION_EU_WEST_1}-ee26b0dd4",
        "ProductArn": f"arn:aws:securityhub:{AWS_REGION_EU_WEST_1}::product/prowler/prowler",
        "RecordState": "ACTIVE",
        "ProductFields": {
            "ProviderName": "Prowler",
            "ProviderVersion": prowler_version,
            "ProwlerResourceName": "test",
        },
        "GeneratorId": "prowler-iam_user_accesskey_unused",
        "AwsAccountId": f"{AWS_ACCOUNT_NUMBER}",
        "Types": ["Software and Configuration Checks"],
        "FirstObservedAt": timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "UpdatedAt": timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "CreatedAt": timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "Severity": {"Label": "LOW"},
        "Title": "Ensure Access Keys unused are disabled",
        "Description": "test",
        "Resources": [
            {
                "Type": "AwsIamAccessAnalyzer",
                "Id": "test",
                "Partition": "aws",
                "Region": f"{AWS_REGION_EU_WEST_1}",
            }
        ],
        "Compliance": {
            "Status": status,
            "RelatedRequirements": [],
            "AssociatedStandards": [],
        },
        "Remediation": {
            "Recommendation": {
                "Text": "Run sudo yum update and cross your fingers and toes.",
                "Url": "https://myfp.com/recommendations/dangerous_things_and_how_to_fix_them.html",
            }
        },
    }


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


class Test_SecurityHub:
    def generate_finding(self, status, region):
        finding = Check_Report(
            load_check_metadata(
                f"{path.dirname(path.realpath(__file__))}/fixtures/metadata.json"
            ).json()
        )
        finding.status = status
        finding.status_extended = "test"
        finding.resource_id = "test"
        finding.resource_arn = "test"
        finding.region = region

        return finding

    def set_mocked_output_options(
        self, status: list[str] = [], send_sh_only_fails: bool = False
    ):
        output_options = MagicMock
        output_options.bulk_checks_metadata = {}
        output_options.status = status
        output_options.send_sh_only_fails = send_sh_only_fails

        return output_options

    def set_mocked_session(self, region):
        # Create mock session
        return session.Session(
            region_name=region,
        )

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_verify_security_hub_integration_enabled_per_region(self):
        session = self.set_mocked_session(AWS_REGION_EU_WEST_1)
        assert verify_security_hub_integration_enabled_per_region(
            AWS_COMMERCIAL_PARTITION, AWS_REGION_EU_WEST_1, session, AWS_ACCOUNT_NUMBER
        )

    def test_verify_security_hub_integration_enabled_per_region_security_hub_disabled(
        self, caplog
    ):
        caplog.set_level(WARNING)
        session = self.set_mocked_session(AWS_REGION_EU_WEST_1)

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
                    f"ClientError -- [67]: An error occurred ({error_code}) when calling the {operation_name} operation: {error_message}",
                )
            ]

    def test_verify_security_hub_integration_enabled_per_region_prowler_not_subscribed(
        self, caplog
    ):
        caplog.set_level(WARNING)
        session = self.set_mocked_session(AWS_REGION_EU_WEST_1)

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
        session = self.set_mocked_session(AWS_REGION_EU_WEST_1)

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
                    f"ClientError -- [67]: An error occurred ({error_code}) when calling the {operation_name} operation: {error_message}",
                )
            ]

    def test_verify_security_hub_integration_enabled_per_region_another_Exception(
        self, caplog
    ):
        caplog.set_level(WARNING)
        session = self.set_mocked_session(AWS_REGION_EU_WEST_1)

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
                    f"Exception -- [67]: {error_message}",
                )
            ]

    def test_prepare_security_hub_findings_enabled_region_all_statuses(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        output_options = self.set_mocked_output_options()
        findings = [self.generate_finding("PASS", AWS_REGION_EU_WEST_1)]
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_EU_WEST_2]
        )

        assert prepare_security_hub_findings(
            findings,
            aws_provider,
            output_options,
            enabled_regions,
        ) == {
            AWS_REGION_EU_WEST_1: [get_security_hub_finding("PASSED")],
        }

    def test_prepare_security_hub_findings_all_statuses_MANUAL_finding(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        output_options = self.set_mocked_output_options()
        findings = [self.generate_finding("MANUAL", AWS_REGION_EU_WEST_1)]
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_EU_WEST_2]
        )

        assert prepare_security_hub_findings(
            findings,
            aws_provider,
            output_options,
            enabled_regions,
        ) == {AWS_REGION_EU_WEST_1: []}

    def test_prepare_security_hub_findings_disabled_region(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        output_options = self.set_mocked_output_options()
        findings = [self.generate_finding("PASS", AWS_REGION_EU_WEST_2)]
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_EU_WEST_2]
        )

        assert prepare_security_hub_findings(
            findings,
            aws_provider,
            output_options,
            enabled_regions,
        ) == {AWS_REGION_EU_WEST_1: []}

    def test_prepare_security_hub_findings_PASS_and_FAIL_statuses(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        output_options = self.set_mocked_output_options(status=["FAIL"])
        findings = [self.generate_finding("PASS", AWS_REGION_EU_WEST_1)]
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_EU_WEST_2]
        )

        assert prepare_security_hub_findings(
            findings,
            aws_provider,
            output_options,
            enabled_regions,
        ) == {AWS_REGION_EU_WEST_1: []}

    def test_prepare_security_hub_findings_FAIL_and_FAIL_statuses(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        output_options = self.set_mocked_output_options(status=["FAIL"])
        findings = [self.generate_finding("FAIL", AWS_REGION_EU_WEST_1)]
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_EU_WEST_2]
        )

        assert prepare_security_hub_findings(
            findings,
            aws_provider,
            output_options,
            enabled_regions,
        ) == {AWS_REGION_EU_WEST_1: [get_security_hub_finding("FAILED")]}

    def test_prepare_security_hub_findings_send_sh_only_fails_PASS(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        output_options = self.set_mocked_output_options(send_sh_only_fails=True)
        findings = [self.generate_finding("PASS", AWS_REGION_EU_WEST_1)]
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_EU_WEST_2]
        )

        assert prepare_security_hub_findings(
            findings,
            aws_provider,
            output_options,
            enabled_regions,
        ) == {AWS_REGION_EU_WEST_1: []}

    def test_prepare_security_hub_findings_send_sh_only_fails_FAIL(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        output_options = self.set_mocked_output_options(send_sh_only_fails=True)
        findings = [self.generate_finding("FAIL", AWS_REGION_EU_WEST_1)]
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_EU_WEST_2]
        )

        assert prepare_security_hub_findings(
            findings,
            aws_provider,
            output_options,
            enabled_regions,
        ) == {AWS_REGION_EU_WEST_1: [get_security_hub_finding("FAILED")]}

    def test_prepare_security_hub_findings_no_audited_regions(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        output_options = self.set_mocked_output_options()
        findings = [self.generate_finding("PASS", AWS_REGION_EU_WEST_1)]
        aws_provider = set_mocked_aws_provider()

        assert prepare_security_hub_findings(
            findings,
            aws_provider,
            output_options,
            enabled_regions,
        ) == {
            AWS_REGION_EU_WEST_1: [get_security_hub_finding("PASSED")],
        }

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_batch_send_to_security_hub_one_finding(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        output_options = self.set_mocked_output_options()
        findings = [self.generate_finding("PASS", AWS_REGION_EU_WEST_1)]
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_EU_WEST_2]
        )
        session = self.set_mocked_session(AWS_REGION_EU_WEST_1)

        security_hub_findings = prepare_security_hub_findings(
            findings,
            aws_provider,
            output_options,
            enabled_regions,
        )

        assert (
            batch_send_to_security_hub(
                security_hub_findings,
                session,
            )
            == 1
        )
