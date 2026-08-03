import json
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

CHECK_MODULE = (
    "prowler.providers.aws.services.kms.kms_key_enclave_attestation_no_deployment_binding"
    ".kms_key_enclave_attestation_no_deployment_binding"
)

PCR0_HASH = "a" * 96
PCR4_HASH = "b" * 96
PCR8_HASH = "c" * 96
PCR1_HASH = "d" * 96


def _policy(*statements):
    return {"Version": "2012-10-17", "Id": "enclave-key", "Statement": list(statements)}


def _sensitive_allow(condition):
    return {
        "Sid": "EnclaveData",
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::123456789012:role/enclave-parent"},
        "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
        "Resource": "*",
        "Condition": condition,
    }


def _create_enclave_tagged_key(kms, policy):
    return kms.create_key(
        MultiRegion=False,
        Policy=json.dumps(policy),
        Tags=[{"TagKey": "prowler:enclave-key", "TagValue": "true"}],
    )["KeyMetadata"]


def _run(policy):
    from prowler.providers.aws.services.kms.kms_service import KMS

    kms_native = client("kms", region_name=AWS_REGION_US_EAST_1)
    key = _create_enclave_tagged_key(kms_native, policy)
    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    kms_service = KMS(aws_provider)

    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(f"{CHECK_MODULE}.kms_client", new=kms_service),
    ):
        from prowler.providers.aws.services.kms.kms_key_enclave_attestation_no_deployment_binding.kms_key_enclave_attestation_no_deployment_binding import (
            kms_key_enclave_attestation_no_deployment_binding,
        )

        return kms_key_enclave_attestation_no_deployment_binding().execute(), key


class Test_kms_key_enclave_attestation_no_deployment_binding:
    @mock_aws
    def test_no_keys_returns_empty(self):
        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.kms_client", new=KMS(aws_provider)),
        ):
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_no_deployment_binding.kms_key_enclave_attestation_no_deployment_binding import (
                kms_key_enclave_attestation_no_deployment_binding,
            )

            assert kms_key_enclave_attestation_no_deployment_binding().execute() == []

    @mock_aws
    def test_non_enclave_key_skipped(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        kms.create_key(MultiRegion=False)

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.kms_client", new=KMS(aws_provider)),
        ):
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_no_deployment_binding.kms_key_enclave_attestation_no_deployment_binding import (
                kms_key_enclave_attestation_no_deployment_binding,
            )

            assert kms_key_enclave_attestation_no_deployment_binding().execute() == []

    @mock_aws
    def test_key_without_attestation_reports_honest_manual(self):
        # No sensitive Allow with attestation → cannot evaluate deployment
        # binding here (covered by attestation_not_enforced). Emit MANUAL
        # with an honest message, NOT a vacuous PASS.
        policy = _policy(
            {
                "Sid": "RootAdminAllData",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": "kms:*",
                "Resource": "*",
            }
        )
        result, key = _run(policy)
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "not applicable" in result[0].status_extended
        assert "attestation_not_enforced" in result[0].status_extended

    @mock_aws
    def test_pcr0_only_reports_fail(self):
        policy = _policy(
            _sensitive_allow(
                {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:PCR0": PCR0_HASH}}
            )
        )
        result, _ = _run(policy)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "PCR0/PCR1/PCR2" in result[0].status_extended

    @mock_aws
    def test_pcr0_and_pcr4_pass(self):
        policy = _policy(
            _sensitive_allow(
                {
                    "StringEqualsIgnoreCase": {
                        "kms:RecipientAttestation:PCR0": PCR0_HASH,
                        "kms:RecipientAttestation:PCR4": PCR4_HASH,
                    }
                }
            )
        )
        result, _ = _run(policy)
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "deployment context" in result[0].status_extended

    @mock_aws
    def test_pcr0_and_pcr8_pass(self):
        policy = _policy(
            _sensitive_allow(
                {
                    "StringEqualsIgnoreCase": {
                        "kms:RecipientAttestation:PCR0": PCR0_HASH,
                        "kms:RecipientAttestation:PCR8": PCR8_HASH,
                    }
                }
            )
        )
        result, _ = _run(policy)
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_pcr0_and_pcr1_fail(self):
        # PCR1 (kernel) is image identity, not deployment context.
        # Per AWS docs, only PCR3/PCR4/PCR8 bind deployment.
        policy = _policy(
            _sensitive_allow(
                {
                    "StringEqualsIgnoreCase": {
                        "kms:RecipientAttestation:PCR0": PCR0_HASH,
                        "kms:RecipientAttestation:PCR1": PCR1_HASH,
                    }
                }
            )
        )
        result, _ = _run(policy)
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_pcr0_and_pcr2_fail(self):
        # PCR2 (application) is image identity, not deployment context.
        policy = _policy(
            _sensitive_allow(
                {
                    "StringEqualsIgnoreCase": {
                        "kms:RecipientAttestation:PCR0": PCR0_HASH,
                        "kms:RecipientAttestation:PCR2": "e" * 96,
                    }
                }
            )
        )
        result, _ = _run(policy)
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_pcr0_and_pcr3_pass(self):
        # PCR3 = parent IAM role, AWS-recommended deployment binding.
        policy = _policy(
            _sensitive_allow(
                {
                    "StringEqualsIgnoreCase": {
                        "kms:RecipientAttestation:PCR0": PCR0_HASH,
                        "kms:RecipientAttestation:PCR3": "f" * 96,
                    }
                }
            )
        )
        result, _ = _run(policy)
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_account_condition_alongside_attestation_pass(self):
        policy = _policy(
            _sensitive_allow(
                {
                    "StringEquals": {
                        "kms:RecipientAttestation:PCR0": PCR0_HASH,
                        "aws:PrincipalAccount": "123456789012",
                    }
                }
            )
        )
        result, _ = _run(policy)
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_account_condition_without_attestation_manual(self):
        # aws:PrincipalAccount alone without any RecipientAttestation binding
        # is NOT deployment binding for this check (attestation must exist).
        policy = _policy(
            _sensitive_allow({"StringEquals": {"aws:PrincipalAccount": "123456789012"}})
        )
        result, _ = _run(policy)
        assert len(result) == 1
        # No attestation at all → MANUAL (covered by attestation_not_enforced).
        assert result[0].status == "MANUAL"

    @mock_aws
    def test_wildcard_account_value_not_restrictive_fail(self):
        # aws:PrincipalAccount with a wildcard value is not restrictive.
        policy = _policy(
            _sensitive_allow(
                {
                    "StringEquals": {
                        "kms:RecipientAttestation:PCR0": PCR0_HASH,
                        "aws:PrincipalAccount": "12345*",
                    }
                }
            )
        )
        result, _ = _run(policy)
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_imagesha384_alone_fail(self):
        # ImageSha384 collapses to PCR0; without PCR4/PCR8/account → INFO.
        policy = _policy(
            _sensitive_allow(
                {
                    "StringEqualsIgnoreCase": {
                        "kms:RecipientAttestation:ImageSha384": PCR0_HASH
                    }
                }
            )
        )
        result, _ = _run(policy)
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_per_statement_evaluation_fails_when_any_lacks_binding(self):
        # Two attestation statements: one with PCR4, one with only PCR0.
        # RFC-compliant is per-statement evaluation, so the check reports
        # INFO because a caller could hit the PCR0-only statement.
        policy = _policy(
            _sensitive_allow(
                {
                    "StringEqualsIgnoreCase": {
                        "kms:RecipientAttestation:PCR0": PCR0_HASH,
                        "kms:RecipientAttestation:PCR4": PCR4_HASH,
                    }
                }
            ),
            {
                "Sid": "PCR0Only",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:role/other"},
                "Action": ["kms:Decrypt"],
                "Resource": "*",
                "Condition": {
                    "StringEqualsIgnoreCase": {
                        "kms:RecipientAttestation:PCR0": PCR0_HASH,
                    }
                },
            },
        )
        result, _ = _run(policy)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "PCR0Only" in result[0].status_extended

    @mock_aws
    def test_forallvalues_pcr4_without_null_guard_manual(self):
        # ForAllValues:StringEquals is vacuous-true when the key is absent
        # unless Null:false locks presence. Without Null:false → not counted.
        policy = _policy(
            _sensitive_allow(
                {
                    "ForAllValues:StringEqualsIgnoreCase": {
                        "kms:RecipientAttestation:PCR0": PCR0_HASH,
                        "kms:RecipientAttestation:PCR4": PCR4_HASH,
                    }
                }
            )
        )
        result, _ = _run(policy)
        assert len(result) == 1
        assert result[0].status == "MANUAL"

    @mock_aws
    def test_case_insensitive_attestation_keys_recognized(self):
        # kms:recipientattestation:pcr4 (lowercase) still recognized.
        policy = _policy(
            _sensitive_allow(
                {
                    "StringEqualsIgnoreCase": {
                        "kms:RecipientAttestation:PCR0": PCR0_HASH,
                        "kms:recipientattestation:pcr4": PCR4_HASH,
                    }
                }
            )
        )
        result, _ = _run(policy)
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_org_id_condition_pass(self):
        policy = _policy(
            _sensitive_allow(
                {
                    "StringEquals": {
                        "kms:RecipientAttestation:PCR0": PCR0_HASH,
                        "aws:PrincipalOrgID": "o-abc123def456",
                    }
                }
            )
        )
        result, _ = _run(policy)
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_policy_fetch_error_reports_manual(self):
        # Simulate a GetKeyPolicy failure and confirm the check emits MANUAL
        # rather than silently skipping the key (fail-closed on missing
        # visibility).
        policy = _policy(
            _sensitive_allow(
                {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:PCR0": PCR0_HASH}}
            )
        )
        from prowler.providers.aws.services.kms.kms_service import KMS

        kms_native = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_tagged_key(kms_native, policy)
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        kms_service = KMS(aws_provider)
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
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_no_deployment_binding.kms_key_enclave_attestation_no_deployment_binding import (
                kms_key_enclave_attestation_no_deployment_binding,
            )

            result = kms_key_enclave_attestation_no_deployment_binding().execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "policy could not be fetched" in result[0].status_extended
            assert "AccessDeniedException" in result[0].status_extended

    @mock_aws
    def test_string_equals_if_exists_account_condition_does_not_bind(self):
        # StringEqualsIfExists is vacuous-true when the request-context key is
        # absent — a caller can bypass by not sending aws:PrincipalAccount.
        # Should NOT satisfy deployment binding.
        policy = _policy(
            _sensitive_allow(
                {
                    "StringEqualsIgnoreCase": {
                        "kms:RecipientAttestation:PCR0": PCR0_HASH
                    },
                    "StringEqualsIfExists": {"aws:PrincipalAccount": "123456789012"},
                }
            )
        )
        result, _ = _run(policy)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "lack deployment-context binding" in result[0].status_extended

    @mock_aws
    def test_arn_like_account_condition_does_not_bind(self):
        # ArnLike allows wildcards — does not bind to a specific ARN.
        policy = _policy(
            _sensitive_allow(
                {
                    "StringEqualsIgnoreCase": {
                        "kms:RecipientAttestation:PCR0": PCR0_HASH
                    },
                    "ArnLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/*"},
                }
            )
        )
        result, _ = _run(policy)
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_for_any_value_string_equals_account_condition_does_not_bind(self):
        # ForAnyValue:StringEquals matches if ANY value in a multi-valued
        # context matches — not strictly restrictive.
        policy = _policy(
            _sensitive_allow(
                {
                    "StringEqualsIgnoreCase": {
                        "kms:RecipientAttestation:PCR0": PCR0_HASH
                    },
                    "ForAnyValue:StringEquals": {
                        "aws:PrincipalAccount": "123456789012"
                    },
                }
            )
        )
        result, _ = _run(policy)
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_for_all_values_string_equals_account_condition_does_not_bind(self):
        # ForAllValues:* is vacuous-true when the key is absent.
        policy = _policy(
            _sensitive_allow(
                {
                    "StringEqualsIgnoreCase": {
                        "kms:RecipientAttestation:PCR0": PCR0_HASH
                    },
                    "ForAllValues:StringEquals": {
                        "aws:PrincipalAccount": "123456789012"
                    },
                }
            )
        )
        result, _ = _run(policy)
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_arn_equals_on_non_account_key_does_not_bind_fail(self):
        # Only ``aws:PrincipalAccount``, ``aws:SourceAccount``,
        # ``aws:PrincipalOrgID``, ``aws:ResourceAccount``, and
        # ``aws:PrincipalOrgPaths`` count as account/org bindings —
        # ``aws:SourceArn`` and ``aws:PrincipalArn`` do not, regardless of
        # operator. Documents the intentional scope of the account allow-list.
        policy = _policy(
            _sensitive_allow(
                {
                    "StringEqualsIgnoreCase": {
                        "kms:RecipientAttestation:PCR0": PCR0_HASH
                    },
                    "ArnEquals": {
                        "aws:SourceArn": (
                            "arn:aws:iam::123456789012:role/enclave-parent"
                        )
                    },
                }
            )
        )
        result, _ = _run(policy)
        assert len(result) == 1
        assert result[0].status == "FAIL"
