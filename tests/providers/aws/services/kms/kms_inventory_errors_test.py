from contextlib import ExitStack
from unittest import mock

import pytest
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

KMS_CHECKS = (
    "kms_cmk_are_used",
    "kms_cmk_not_deleted_unintentionally",
    "kms_cmk_not_multi_region",
    "kms_cmk_rotation_enabled",
    "kms_key_not_publicly_accessible",
    "kms_key_enclave_attestation_not_enforced",
    "kms_key_enclave_attestation_no_deployment_binding",
    "kms_key_enclave_attestation_unknown_image",
    "kms_key_enclave_attestation_bypassable_path",
    "kms_key_enclave_attestation_pcr_mismatch",
    "kms_key_enclave_debug_attestation_detected",
)

DETAIL_DEPENDENT_CHECKS = tuple(
    check
    for check in KMS_CHECKS
    if check
    not in {
        "kms_key_enclave_attestation_unknown_image",
        "kms_key_enclave_debug_attestation_detected",
    }
)


class FakeKMSClient:
    def __init__(self, keys=None, scan_errors=None):
        self.keys = keys or []
        self.keys_scan_errors = scan_errors or {}
        self.audited_partition = "aws"
        self.audited_account = AWS_ACCOUNT_NUMBER
        self.region = AWS_REGION_US_EAST_1
        self.audit_config = {}


class IncompleteKey:
    def __init__(self):
        self.id = "incomplete-key"
        self.arn = (
            f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/{self.id}"
        )
        self.region = AWS_REGION_US_EAST_1
        self.tags = []
        self.manager = None
        self.state = None
        self.origin = None
        self.spec = None
        self.multi_region = None
        self.rotation_enabled = None
        self.policy = None
        self.detail_retrieved = False
        self.detail_fetch_error = "AccessDeniedException"

    def dict(self):
        return self.__dict__


def _get_check_class(check_name):
    if check_name == "kms_cmk_are_used":
        from prowler.providers.aws.services.kms.kms_cmk_are_used.kms_cmk_are_used import (
            kms_cmk_are_used,
        )

        return kms_cmk_are_used
    if check_name == "kms_cmk_not_deleted_unintentionally":
        from prowler.providers.aws.services.kms.kms_cmk_not_deleted_unintentionally.kms_cmk_not_deleted_unintentionally import (
            kms_cmk_not_deleted_unintentionally,
        )

        return kms_cmk_not_deleted_unintentionally
    if check_name == "kms_cmk_not_multi_region":
        from prowler.providers.aws.services.kms.kms_cmk_not_multi_region.kms_cmk_not_multi_region import (
            kms_cmk_not_multi_region,
        )

        return kms_cmk_not_multi_region
    if check_name == "kms_cmk_rotation_enabled":
        from prowler.providers.aws.services.kms.kms_cmk_rotation_enabled.kms_cmk_rotation_enabled import (
            kms_cmk_rotation_enabled,
        )

        return kms_cmk_rotation_enabled
    if check_name == "kms_key_not_publicly_accessible":
        from prowler.providers.aws.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible import (
            kms_key_not_publicly_accessible,
        )

        return kms_key_not_publicly_accessible
    if check_name == "kms_key_enclave_attestation_not_enforced":
        from prowler.providers.aws.services.kms.kms_key_enclave_attestation_not_enforced.kms_key_enclave_attestation_not_enforced import (
            kms_key_enclave_attestation_not_enforced,
        )

        return kms_key_enclave_attestation_not_enforced
    if check_name == "kms_key_enclave_attestation_no_deployment_binding":
        from prowler.providers.aws.services.kms.kms_key_enclave_attestation_no_deployment_binding.kms_key_enclave_attestation_no_deployment_binding import (
            kms_key_enclave_attestation_no_deployment_binding,
        )

        return kms_key_enclave_attestation_no_deployment_binding
    if check_name == "kms_key_enclave_attestation_unknown_image":
        from prowler.providers.aws.services.kms.kms_key_enclave_attestation_unknown_image.kms_key_enclave_attestation_unknown_image import (
            kms_key_enclave_attestation_unknown_image,
        )

        return kms_key_enclave_attestation_unknown_image
    if check_name == "kms_key_enclave_attestation_bypassable_path":
        from prowler.providers.aws.services.kms.kms_key_enclave_attestation_bypassable_path.kms_key_enclave_attestation_bypassable_path import (
            kms_key_enclave_attestation_bypassable_path,
        )

        return kms_key_enclave_attestation_bypassable_path
    if check_name == "kms_key_enclave_attestation_pcr_mismatch":
        from prowler.providers.aws.services.kms.kms_key_enclave_attestation_pcr_mismatch.kms_key_enclave_attestation_pcr_mismatch import (
            kms_key_enclave_attestation_pcr_mismatch,
        )

        return kms_key_enclave_attestation_pcr_mismatch
    if check_name == "kms_key_enclave_debug_attestation_detected":
        from prowler.providers.aws.services.kms.kms_key_enclave_debug_attestation_detected.kms_key_enclave_debug_attestation_detected import (
            kms_key_enclave_debug_attestation_detected,
        )

        return kms_key_enclave_debug_attestation_detected
    raise AssertionError(f"Unsupported check: {check_name}")


def _execute_with_client(check_name, kms_client):
    provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    with mock.patch(
        "prowler.providers.common.provider.Provider.get_global_provider",
        return_value=provider,
    ):
        check_class = _get_check_class(check_name)
        with ExitStack() as stack:
            stack.enter_context(
                mock.patch(f"{check_class.__module__}.kms_client", new=kms_client)
            )
            if check_name in {
                "kms_key_enclave_attestation_unknown_image",
                "kms_key_enclave_debug_attestation_detected",
            }:
                cloudtrail_client = mock.MagicMock()
                cloudtrail_client.trails = {}
                cloudtrail_client.regional_clients = {}
                stack.enter_context(
                    mock.patch(
                        f"{check_class.__module__}.cloudtrail_client",
                        new=cloudtrail_client,
                    )
                )
            return check_class().execute()


@pytest.mark.parametrize("check_name", KMS_CHECKS)
@mock_aws
def test_kms_check_reports_regional_inventory_error(check_name):
    kms_client = FakeKMSClient(
        scan_errors={AWS_REGION_US_EAST_1: "AccessDeniedException"}
    )

    result = _execute_with_client(check_name, kms_client)

    inventory_finding = next(
        finding
        for finding in result
        if finding.resource_id == "key/unknown"
        and "could not be listed" in finding.status_extended
    )
    assert inventory_finding.status == "MANUAL"
    assert inventory_finding.region == AWS_REGION_US_EAST_1
    assert inventory_finding.resource_arn == (
        f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/unknown"
    )
    assert "AccessDeniedException" in inventory_finding.status_extended


@pytest.mark.parametrize("check_name", DETAIL_DEPENDENT_CHECKS)
@mock_aws
def test_kms_check_reports_incomplete_key_detail(check_name):
    kms_client = FakeKMSClient(keys=[IncompleteKey()])

    result = _execute_with_client(check_name, kms_client)

    assert len(result) == 1
    assert result[0].status == "MANUAL"
    assert result[0].resource_id == "incomplete-key"
    assert "could not be described" in result[0].status_extended
    assert "AccessDeniedException" in result[0].status_extended
