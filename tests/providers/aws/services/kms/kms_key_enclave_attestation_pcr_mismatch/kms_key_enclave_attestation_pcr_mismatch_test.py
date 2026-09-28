import json
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

CHECK_MODULE = (
    "prowler.providers.aws.services.kms.kms_key_enclave_attestation_pcr_mismatch"
    ".kms_key_enclave_attestation_pcr_mismatch"
)

PCR0_GOLD = "a" * 96
PCR0_BAD = "b" * 96
PCR1_GOLD = "c" * 96
PCR8_GOLD = "d" * 96


def _enclave_policy(condition, action="kms:Decrypt"):
    return {
        "Version": "2012-10-17",
        "Id": "enclave-key",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:role/enclave-parent"},
                "Action": action,
                "Resource": "*",
                "Condition": condition,
            }
        ],
    }


def _create_enclave_key(kms, condition, tags=None):
    if tags is None:
        tags = [{"TagKey": "prowler:enclave-key", "TagValue": "true"}]
    return kms.create_key(
        MultiRegion=False,
        Policy=json.dumps(_enclave_policy(condition)),
        Tags=tags,
    )["KeyMetadata"]


def _run_check(golden_config):
    from prowler.providers.aws.services.kms.kms_service import KMS

    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    if golden_config is not None:
        aws_provider._audit_config = {"enclave_golden_pcr_values": golden_config}

    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(f"{CHECK_MODULE}.kms_client", new=KMS(aws_provider)),
    ):
        from prowler.providers.aws.services.kms.kms_key_enclave_attestation_pcr_mismatch.kms_key_enclave_attestation_pcr_mismatch import (
            kms_key_enclave_attestation_pcr_mismatch,
        )

        return kms_key_enclave_attestation_pcr_mismatch().execute()


class Test_kms_key_enclave_attestation_pcr_mismatch:
    @mock_aws
    def test_no_keys(self):
        assert _run_check({"PCR0": [PCR0_GOLD]}) == []

    @mock_aws
    def test_non_enclave_key_skipped(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        kms.create_key(MultiRegion=False)  # no enclave tag, no attestation

        assert _run_check({"PCR0": [PCR0_GOLD]}) == []

    @mock_aws
    def test_no_config_reports_manual(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        _create_enclave_key(
            kms,
            {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:PCR0": PCR0_GOLD}},
        )

        result = _run_check(None)
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "no 'enclave_golden_pcr_values'" in result[0].status_extended

    @mock_aws
    def test_empty_config_reports_manual(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        _create_enclave_key(
            kms,
            {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:PCR0": PCR0_GOLD}},
        )

        result = _run_check({})
        assert len(result) == 1
        assert result[0].status == "MANUAL"

    @mock_aws
    def test_pcr0_in_golden_list_pass(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        _create_enclave_key(
            kms,
            {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:PCR0": PCR0_GOLD}},
        )

        result = _run_check({"PCR0": [PCR0_GOLD]})
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_pcr0_not_in_golden_list_fail(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        _create_enclave_key(
            kms,
            {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:PCR0": PCR0_BAD}},
        )

        result = _run_check({"PCR0": [PCR0_GOLD]})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "PCR0" in result[0].status_extended
        assert PCR0_BAD in result[0].status_extended

    @mock_aws
    def test_imagesha384_collapses_to_pcr0(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        _create_enclave_key(
            kms,
            {
                "StringEqualsIgnoreCase": {
                    "kms:RecipientAttestation:ImageSha384": PCR0_GOLD
                }
            },
        )

        result = _run_check({"PCR0": [PCR0_GOLD]})
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_case_insensitive_condition_key_match(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        _create_enclave_key(
            kms,
            {"StringEqualsIgnoreCase": {"kms:recipientattestation:pcr0": PCR0_GOLD}},
        )

        result = _run_check({"PCR0": [PCR0_GOLD]})
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_partial_config_uncovered_pcr_reports_manual(self):
        # Policy binds PCR0 (good) and PCR1 (unknown value). Only PCR0 is
        # configured in the golden list. The PCR1 binding is unverified →
        # fail-closed to MANUAL rather than silent PASS.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        _create_enclave_key(
            kms,
            {
                "StringEqualsIgnoreCase": {
                    "kms:RecipientAttestation:PCR0": PCR0_GOLD,
                    "kms:RecipientAttestation:PCR1": "eeee" * 24,
                }
            },
        )

        result = _run_check({"PCR0": [PCR0_GOLD]})
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "PCR1" in result[0].status_extended
        assert "no golden list is configured" in result[0].status_extended

    @mock_aws
    def test_all_pcrs_covered_and_matching_pass(self):
        # Policy binds PCR0 + PCR1; both are configured and both values are in
        # their respective golden lists → PASS.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        _create_enclave_key(
            kms,
            {
                "StringEqualsIgnoreCase": {
                    "kms:RecipientAttestation:PCR0": PCR0_GOLD,
                    "kms:RecipientAttestation:PCR1": PCR1_GOLD,
                }
            },
        )

        result = _run_check({"PCR0": [PCR0_GOLD], "PCR1": [PCR1_GOLD]})
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_configured_pcr_never_referenced_reports_manual(self):
        # Policy only binds PCR0; golden list only configures PCR8. PCR0 is
        # uncovered → MANUAL with the uncovered-PCRs message.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        _create_enclave_key(
            kms,
            {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:PCR0": PCR0_GOLD}},
        )

        result = _run_check({"PCR8": [PCR8_GOLD]})
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "PCR0" in result[0].status_extended
        assert "no golden list is configured" in result[0].status_extended

    @mock_aws
    def test_empty_value_list_for_pcr_treated_as_unconfigured(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        _create_enclave_key(
            kms,
            {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:PCR0": PCR0_BAD}},
        )

        # Only PCR1 has a non-empty list, so PCR0 is not verified and PCR1 is
        # not referenced → MANUAL.
        result = _run_check({"PCR0": [], "PCR1": [PCR1_GOLD]})
        assert len(result) == 1
        assert result[0].status == "MANUAL"

    @mock_aws
    def test_value_list_contains_wildcard_skipped(self):
        # attestation_condition_keys already filters wildcards out. A policy
        # with only a wildcard binding cannot be verified against a golden
        # list, so nothing is checked → MANUAL.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        _create_enclave_key(
            kms,
            {"StringLike": {"kms:RecipientAttestation:PCR0": PCR0_GOLD + "*"}},
        )

        result = _run_check({"PCR0": [PCR0_GOLD]})
        assert len(result) == 1
        assert result[0].status == "MANUAL"

    @mock_aws
    def test_pcr_value_list_with_one_bad_entry_fails(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        _create_enclave_key(
            kms,
            {
                "StringEqualsIgnoreCase": {
                    "kms:RecipientAttestation:PCR0": [PCR0_GOLD, PCR0_BAD]
                }
            },
        )

        result = _run_check({"PCR0": [PCR0_GOLD]})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert PCR0_BAD in result[0].status_extended
        assert PCR0_GOLD not in result[0].status_extended

    @mock_aws
    def test_value_compare_case_insensitive(self):
        # Golden values are lowercased at load; policy values are lowercased
        # at read. Mixed-case hex must still match.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        _create_enclave_key(
            kms,
            {
                "StringEqualsIgnoreCase": {
                    "kms:RecipientAttestation:PCR0": PCR0_GOLD.upper()
                }
            },
        )

        result = _run_check({"PCR0": [PCR0_GOLD]})
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_multiple_keys_mixed_verdicts(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        _create_enclave_key(
            kms,
            {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:PCR0": PCR0_GOLD}},
        )
        _create_enclave_key(
            kms,
            {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:PCR0": PCR0_BAD}},
        )
        _create_enclave_key(
            kms,
            {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:PCR8": PCR8_GOLD}},
        )

        result = _run_check({"PCR0": [PCR0_GOLD]})
        statuses = sorted(r.status for r in result)
        assert statuses == ["FAIL", "MANUAL", "PASS"]

    @mock_aws
    def test_non_sensitive_action_ignored(self):
        # Attestation binding on kms:ListKeys (non-sensitive) does not trigger
        # golden verification: the policy has no sensitive statement to check
        # → MANUAL (nothing verified).
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        kms.create_key(
            MultiRegion=False,
            Policy=json.dumps(
                _enclave_policy(
                    {
                        "StringEqualsIgnoreCase": {
                            "kms:RecipientAttestation:PCR0": PCR0_BAD
                        }
                    },
                    action="kms:ListKeys",
                )
            ),
            Tags=[{"TagKey": "prowler:enclave-key", "TagValue": "true"}],
        )

        result = _run_check({"PCR0": [PCR0_GOLD]})
        assert len(result) == 1
        assert result[0].status == "MANUAL"

    @mock_aws
    def test_disabled_key_skipped(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_key(
            kms,
            {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:PCR0": PCR0_BAD}},
        )
        kms.disable_key(KeyId=key["KeyId"])

        assert _run_check({"PCR0": [PCR0_GOLD]}) == []

    @mock_aws
    def test_for_all_values_without_null_guard_ignored(self):
        # ForAllValues:* without Null:false guard was already filtered by
        # attestation_condition_keys as non-restrictive. That statement's PCR
        # bindings must NOT be verified against golden values → MANUAL.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        _create_enclave_key(
            kms,
            {
                "ForAllValues:StringEqualsIgnoreCase": {
                    "kms:RecipientAttestation:PCR0": PCR0_BAD
                }
            },
        )

        result = _run_check({"PCR0": [PCR0_GOLD]})
        assert len(result) == 1
        assert result[0].status == "MANUAL"

    @mock_aws
    def test_for_all_values_with_null_guard_verified(self):
        # ForAllValues + Null:false is restrictive → PCR bindings ARE verified.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        _create_enclave_key(
            kms,
            {
                "ForAllValues:StringEqualsIgnoreCase": {
                    "kms:RecipientAttestation:PCR0": PCR0_BAD
                },
                "Null": {"kms:RecipientAttestation:PCR0": "false"},
            },
        )

        result = _run_check({"PCR0": [PCR0_GOLD]})
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_multi_statement_aggregation(self):
        # Two Allow statements on the same key, each binding PCR0 to a
        # different value. Both values should aggregate into observed. If the
        # golden list covers only one of them, the other value must surface as
        # a mismatch → FAIL.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        policy = {
            "Version": "2012-10-17",
            "Id": "enclave-key",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:role/enclave-parent"
                    },
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                    "Condition": {
                        "StringEqualsIgnoreCase": {
                            "kms:RecipientAttestation:PCR0": PCR0_GOLD
                        }
                    },
                },
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:role/other-parent"},
                    "Action": "kms:GenerateDataKey",
                    "Resource": "*",
                    "Condition": {
                        "StringEqualsIgnoreCase": {
                            "kms:RecipientAttestation:PCR0": PCR0_BAD
                        }
                    },
                },
            ],
        }
        kms.create_key(
            MultiRegion=False,
            Policy=json.dumps(policy),
            Tags=[{"TagKey": "prowler:enclave-key", "TagValue": "true"}],
        )

        result = _run_check({"PCR0": [PCR0_GOLD]})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert PCR0_BAD in result[0].status_extended

    @mock_aws
    def test_not_action_covers_sensitive_actions(self):
        # NotAction that does NOT exclude every sensitive action grants those
        # sensitive actions. The binding should be verified against golden
        # values just like an explicit Action list.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        policy = {
            "Version": "2012-10-17",
            "Id": "enclave-key",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:role/enclave-parent"
                    },
                    "NotAction": "kms:ListKeys",
                    "Resource": "*",
                    "Condition": {
                        "StringEqualsIgnoreCase": {
                            "kms:RecipientAttestation:PCR0": PCR0_BAD
                        }
                    },
                }
            ],
        }
        kms.create_key(
            MultiRegion=False,
            Policy=json.dumps(policy),
            Tags=[{"TagKey": "prowler:enclave-key", "TagValue": "true"}],
        )

        result = _run_check({"PCR0": [PCR0_GOLD]})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert PCR0_BAD in result[0].status_extended

    @mock_aws
    def test_policy_fetch_error_reports_manual(self):
        # GetKeyPolicy failure → MANUAL, not silent skip (fail-closed).
        kms_native = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_key(
            kms_native,
            {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:PCR0": PCR0_GOLD}},
        )

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        kms_service = KMS(aws_provider)
        # Configure golden PCRs directly on the service (aws_provider.audit_config
        # is a read-only property).
        kms_service.audit_config = {"enclave_golden_pcr_values": {"PCR0": [PCR0_GOLD]}}
        for k in kms_service.keys:
            if k.id == key["KeyId"]:
                k.policy = None
                k.policy_fetch_error = "AccessDeniedException"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.kms_client", new=kms_service),
        ):
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_pcr_mismatch.kms_key_enclave_attestation_pcr_mismatch import (
                kms_key_enclave_attestation_pcr_mismatch,
            )

            result = kms_key_enclave_attestation_pcr_mismatch().execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "policy could not be fetched" in result[0].status_extended
            assert "AccessDeniedException" in result[0].status_extended
