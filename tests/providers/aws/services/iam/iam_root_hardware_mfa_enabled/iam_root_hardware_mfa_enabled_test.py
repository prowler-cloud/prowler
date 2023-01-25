from re import search
from unittest import mock

from boto3 import client
from moto import mock_iam


class Test_iam_root_hardware_mfa_enabled_test:
    @mock_iam
    def test_root_hardware_virtual_mfa_enabled(self):
        iam = client("iam")
        mfa_device_name = "mfa-test"
        iam.create_virtual_mfa_device(VirtualMFADeviceName=mfa_device_name)
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.iam.iam_root_hardware_mfa_enabled.iam_root_hardware_mfa_enabled.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_root_hardware_mfa_enabled.iam_root_hardware_mfa_enabled import (
                iam_root_hardware_mfa_enabled,
            )

            service_client.account_summary["SummaryMap"]["AccountMFAEnabled"] = 1
            service_client.virtual_mfa_devices[0]["SerialNumber"] = "sddfaf-root-sfsfds"

            check = iam_root_hardware_mfa_enabled()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert search(
                "Root account has a virtual MFA instead of a hardware MFA device enabled.",
                result[0].status_extended,
            )
            assert result[0].resource_id == "root"

    @mock_iam
    def test_root_hardware_virtual_hardware_mfa_enabled(self):
        iam = client("iam")
        mfa_device_name = "mfa-test"
        iam.create_virtual_mfa_device(VirtualMFADeviceName=mfa_device_name)
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.iam.iam_root_hardware_mfa_enabled.iam_root_hardware_mfa_enabled.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_root_hardware_mfa_enabled.iam_root_hardware_mfa_enabled import (
                iam_root_hardware_mfa_enabled,
            )

            service_client.account_summary["SummaryMap"]["AccountMFAEnabled"] = 1
            service_client.virtual_mfa_devices[0]["SerialNumber"] = ""

            check = iam_root_hardware_mfa_enabled()
            result = check.execute()
            assert result[0].status == "PASS"
            assert search(
                "Root account has a hardware MFA device enabled.",
                result[0].status_extended,
            )
            assert result[0].resource_id == "root"
            assert (
                result[0].resource_arn == f"arn:aws:iam::{service_client.account}:root"
            )
