from argparse import Namespace
from logging import ERROR, WARNING
from os import path

import botocore
from botocore.client import ClientError
from mock import patch

from prowler.config.config import prowler_version, timestamp_utc
from prowler.lib.check.models import Check_Report, load_check_metadata
from prowler.lib.outputs.security_hub.security_hub import SecurityHub
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
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
    def generate_finding(self, status, region, muted=False):
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
        finding.muted = muted

        return finding

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_verify(self):
        aws_provider = set_mocked_aws_provider()
        security_hub = SecurityHub(aws_provider)

        assert security_hub.verify(AWS_REGION_EU_WEST_1)

    def test_verify_security_hub_disabled(self, caplog):
        aws_provider = set_mocked_aws_provider()
        security_hub = SecurityHub(aws_provider)

        caplog.set_level(WARNING)

        with patch(
            "prowler.lib.outputs.security_hub.security_hub.Session.client",
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

            assert not security_hub.verify(
                AWS_REGION_EU_WEST_1,
            )
            assert caplog.record_tuples == [
                (
                    "root",
                    WARNING,
                    f"ClientError -- [83]: An error occurred ({error_code}) when calling the {operation_name} operation: {error_message}",
                )
            ]

    def test_verify_prowler_not_subscribed(self, caplog):
        aws_provider = set_mocked_aws_provider()
        security_hub = SecurityHub(aws_provider)

        caplog.set_level(WARNING)

        with patch(
            "prowler.lib.outputs.security_hub.security_hub.Session.client",
        ) as mock_security_hub:
            mock_security_hub.describe_hub.return_value = None
            mock_security_hub.list_enabled_products_for_import.return_value = []

            assert not security_hub.verify(
                AWS_REGION_EU_WEST_1,
            )
            assert caplog.record_tuples == [
                (
                    "root",
                    WARNING,
                    f"Security Hub is enabled in {AWS_REGION_EU_WEST_1} but Prowler integration does not accept findings. More info: https://docs.prowler.cloud/en/latest/tutorials/aws/securityhub/",
                )
            ]

    def test_verify_another_ClientError(self, caplog):
        aws_provider = set_mocked_aws_provider()
        security_hub = SecurityHub(aws_provider)

        caplog.set_level(WARNING)

        with patch(
            "prowler.lib.outputs.security_hub.security_hub.Session.client",
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

            assert not security_hub.verify(
                AWS_REGION_EU_WEST_1,
            )
            assert caplog.record_tuples == [
                (
                    "root",
                    ERROR,
                    f"ClientError -- [83]: An error occurred ({error_code}) when calling the {operation_name} operation: {error_message}",
                )
            ]

    def test_verify_another_Exception(self, caplog):
        aws_provider = set_mocked_aws_provider()
        security_hub = SecurityHub(aws_provider)

        caplog.set_level(WARNING)

        with patch(
            "prowler.lib.outputs.security_hub.security_hub.Session.client",
        ) as mock_security_hub:
            error_message = f"Another exception in region {AWS_REGION_EU_WEST_1}"
            mock_security_hub.side_effect = Exception(error_message)

            assert not security_hub.verify(
                AWS_REGION_EU_WEST_1,
            )
            assert caplog.record_tuples == [
                (
                    "root",
                    ERROR,
                    f"Exception -- [83]: {error_message}",
                )
            ]

    def test_prepare_enabled_region_all_statuses(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        findings = [self.generate_finding("PASS", AWS_REGION_EU_WEST_1)]
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_EU_WEST_2]
        )
        security_hub = SecurityHub(aws_provider)

        assert security_hub.prepare(
            findings,
            enabled_regions,
        ) == {
            AWS_REGION_EU_WEST_1: [get_security_hub_finding("PASSED")],
        }

    def test_prepare_all_statuses_MANUAL_finding(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        findings = [self.generate_finding("MANUAL", AWS_REGION_EU_WEST_1)]
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_EU_WEST_2]
        )
        security_hub = SecurityHub(aws_provider)

        assert security_hub.prepare(
            findings,
            enabled_regions,
        ) == {AWS_REGION_EU_WEST_1: []}

    def test_prepare_disabled_region(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        findings = [self.generate_finding("PASS", AWS_REGION_EU_WEST_2)]
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_EU_WEST_2]
        )
        security_hub = SecurityHub(aws_provider)

        assert security_hub.prepare(
            findings,
            enabled_regions,
        ) == {AWS_REGION_EU_WEST_1: []}

    def test_prepare_PASS_and_FAIL_statuses(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        findings = [self.generate_finding("PASS", AWS_REGION_EU_WEST_1)]

        args = Namespace()
        args.status = ["FAIL"]
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_EU_WEST_2], arguments=args
        )

        security_hub = SecurityHub(aws_provider)

        assert security_hub.prepare(
            findings,
            enabled_regions,
        ) == {AWS_REGION_EU_WEST_1: []}

    def test_prepare_FAIL_and_FAIL_statuses(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        findings = [self.generate_finding("FAIL", AWS_REGION_EU_WEST_1)]

        args = Namespace()
        args.status = ["FAIL"]
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_EU_WEST_2], arguments=args
        )

        security_hub = SecurityHub(aws_provider)

        assert security_hub.prepare(
            findings,
            enabled_regions,
        ) == {AWS_REGION_EU_WEST_1: [get_security_hub_finding("FAILED")]}

    def test_prepare_send_sh_only_fails_PASS(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        findings = [self.generate_finding("PASS", AWS_REGION_EU_WEST_1)]

        args = Namespace()
        args.send_sh_only_fails = True

        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_EU_WEST_2], arguments=args
        )
        security_hub = SecurityHub(aws_provider)

        assert security_hub.prepare(
            findings,
            enabled_regions,
        ) == {AWS_REGION_EU_WEST_1: []}

    def test_prepare_send_sh_only_fails_FAIL(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        findings = [self.generate_finding("FAIL", AWS_REGION_EU_WEST_1)]

        args = Namespace()
        args.send_sh_only_fails = True

        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_EU_WEST_2], arguments=args
        )
        security_hub = SecurityHub(aws_provider)

        assert security_hub.prepare(
            findings,
            enabled_regions,
        ) == {AWS_REGION_EU_WEST_1: [get_security_hub_finding("FAILED")]}

    def test_prepare_no_audited_regions(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        findings = [self.generate_finding("PASS", AWS_REGION_EU_WEST_1)]

        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_EU_WEST_2]
        )
        security_hub = SecurityHub(aws_provider)

        assert security_hub.prepare(
            findings,
            enabled_regions,
        ) == {
            AWS_REGION_EU_WEST_1: [get_security_hub_finding("PASSED")],
        }

    def test_prepare_muted_fail_with_send_sh_only_fails(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        findings = [
            self.generate_finding(
                status="FAIL", region=AWS_REGION_EU_WEST_1, muted=True
            )
        ]
        args = Namespace()
        args.send_sh_only_fails = True

        aws_provider = set_mocked_aws_provider(arguments=args)
        security_hub = SecurityHub(aws_provider)

        assert security_hub.prepare(
            findings,
            enabled_regions,
        ) == {
            AWS_REGION_EU_WEST_1: [],
        }

    def test_prepare_muted_fail_with_status_FAIL(self):
        enabled_regions = [AWS_REGION_EU_WEST_1]
        findings = [
            self.generate_finding(
                status="FAIL", region=AWS_REGION_EU_WEST_1, muted=True
            )
        ]
        args = Namespace()
        args.status = ["FAIL"]
        aws_provider = set_mocked_aws_provider(arguments=args)
        security_hub = SecurityHub(aws_provider)

        assert security_hub.prepare(
            findings,
            enabled_regions,
        ) == {
            AWS_REGION_EU_WEST_1: [],
        }

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_send_one_finding(self):
        enabled_regions = [AWS_REGION_EU_WEST_1, AWS_REGION_EU_WEST_2]
        findings = [
            self.generate_finding("PASS", AWS_REGION_EU_WEST_1),
            self.generate_finding("FAIL", AWS_REGION_EU_WEST_2),
        ]

        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_EU_WEST_2]
        )
        security_hub = SecurityHub(aws_provider)

        security_hub_findings = security_hub.prepare(
            findings,
            enabled_regions,
        )

        assert (
            security_hub.send(
                security_hub_findings,
            )
            == 2
        )
