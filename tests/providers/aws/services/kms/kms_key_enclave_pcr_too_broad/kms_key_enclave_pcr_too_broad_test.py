import json
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

CHECK_MODULE = (
    "prowler.providers.aws.services.kms.kms_key_enclave_pcr_too_broad"
    ".kms_key_enclave_pcr_too_broad"
)


def _enclave_policy(condition):
    return {
        "Version": "2012-10-17",
        "Id": "enclave-key",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:role/enclave-parent"},
                "Action": "kms:Decrypt",
                "Resource": "*",
                "Condition": condition,
            }
        ],
    }


def _create_enclave_key(kms, condition):
    return kms.create_key(
        MultiRegion=False,
        Policy=json.dumps(_enclave_policy(condition)),
        Tags=[{"TagKey": "prowler:enclave-key", "TagValue": "true"}],
    )["KeyMetadata"]


class Test_kms_key_enclave_pcr_too_broad:
    @mock_aws
    def test_no_keys(self):
        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.kms_client", new=KMS(aws_provider)),
        ):
            from prowler.providers.aws.services.kms.kms_key_enclave_pcr_too_broad.kms_key_enclave_pcr_too_broad import (
                kms_key_enclave_pcr_too_broad,
            )

            assert kms_key_enclave_pcr_too_broad().execute() == []

    @mock_aws
    def test_pcr0_only_fail(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_key(
            kms,
            {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:PCR0": "a" * 96}},
        )

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.kms_client", new=KMS(aws_provider)),
        ):
            from prowler.providers.aws.services.kms.kms_key_enclave_pcr_too_broad.kms_key_enclave_pcr_too_broad import (
                kms_key_enclave_pcr_too_broad,
            )

            result = kms_key_enclave_pcr_too_broad().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == key["KeyId"]
            assert "PCR0" in result[0].status_extended

    @mock_aws
    def test_imagesha384_alone_fail(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_key(
            kms,
            {
                "StringEqualsIgnoreCase": {
                    "kms:RecipientAttestation:ImageSha384": "b" * 96
                }
            },
        )

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.kms_client", new=KMS(aws_provider)),
        ):
            from prowler.providers.aws.services.kms.kms_key_enclave_pcr_too_broad.kms_key_enclave_pcr_too_broad import (
                kms_key_enclave_pcr_too_broad,
            )

            result = kms_key_enclave_pcr_too_broad().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == key["KeyId"]

    @mock_aws
    def test_pcr0_and_imagesha384_collapses_fail(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_key(
            kms,
            {
                "StringEqualsIgnoreCase": {
                    "kms:RecipientAttestation:PCR0": "a" * 96,
                    "kms:RecipientAttestation:ImageSha384": "a" * 96,
                }
            },
        )

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.kms_client", new=KMS(aws_provider)),
        ):
            from prowler.providers.aws.services.kms.kms_key_enclave_pcr_too_broad.kms_key_enclave_pcr_too_broad import (
                kms_key_enclave_pcr_too_broad,
            )

            result = kms_key_enclave_pcr_too_broad().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == key["KeyId"]

    @mock_aws
    def test_pcr0_and_pcr1_pass(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_key(
            kms,
            {
                "StringEqualsIgnoreCase": {
                    "kms:RecipientAttestation:PCR0": "a" * 96,
                    "kms:RecipientAttestation:PCR1": "b" * 96,
                }
            },
        )

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.kms_client", new=KMS(aws_provider)),
        ):
            from prowler.providers.aws.services.kms.kms_key_enclave_pcr_too_broad.kms_key_enclave_pcr_too_broad import (
                kms_key_enclave_pcr_too_broad,
            )

            result = kms_key_enclave_pcr_too_broad().execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == key["KeyId"]

    @mock_aws
    def test_pcr0_and_custom_pcr_pass(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_key(
            kms,
            {
                "StringEqualsIgnoreCase": {
                    "kms:RecipientAttestation:PCR0": "a" * 96,
                    "kms:RecipientAttestation:PCR9": "c" * 96,
                }
            },
        )

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.kms_client", new=KMS(aws_provider)),
        ):
            from prowler.providers.aws.services.kms.kms_key_enclave_pcr_too_broad.kms_key_enclave_pcr_too_broad import (
                kms_key_enclave_pcr_too_broad,
            )

            result = kms_key_enclave_pcr_too_broad().execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == key["KeyId"]

    @mock_aws
    def test_no_attestation_condition_skipped_here(self):
        # No attestation at all is Check 6's job; this check should PASS silently.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        _create_enclave_key(kms, {})

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.kms_client", new=KMS(aws_provider)),
        ):
            from prowler.providers.aws.services.kms.kms_key_enclave_pcr_too_broad.kms_key_enclave_pcr_too_broad import (
                kms_key_enclave_pcr_too_broad,
            )

            result = kms_key_enclave_pcr_too_broad().execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

    @mock_aws
    def test_valid_pcr0_plus_wildcard_pcr1_still_narrow_fail(self):
        # PCR0 is bound restrictively, but PCR1 uses StringLike with "*" so it
        # doesn't count as a real binding. Effective bindings = 1 → FAIL.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_key(
            kms,
            {
                "StringEqualsIgnoreCase": {
                    "kms:RecipientAttestation:PCR0": "a" * 96,
                },
                "StringLike": {
                    "kms:RecipientAttestation:PCR1": "*",
                },
            },
        )

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.kms_client", new=KMS(aws_provider)),
        ):
            from prowler.providers.aws.services.kms.kms_key_enclave_pcr_too_broad.kms_key_enclave_pcr_too_broad import (
                kms_key_enclave_pcr_too_broad,
            )

            result = kms_key_enclave_pcr_too_broad().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == key["KeyId"]

    @mock_aws
    def test_mixed_case_pcr0_and_canonical_pcr0_collapse_to_one_binding_fail(self):
        # AWS condition keys are case-insensitive: `pcr0` and `PCR0` are the
        # same binding. Check 9 must not count them as two distinct PCRs.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_key(
            kms,
            {
                "StringEqualsIgnoreCase": {
                    "kms:RecipientAttestation:PCR0": "a" * 96,
                    "KMS:recipientAttestation:pcr0": "a" * 96,
                }
            },
        )

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.kms_client", new=KMS(aws_provider)),
        ):
            from prowler.providers.aws.services.kms.kms_key_enclave_pcr_too_broad.kms_key_enclave_pcr_too_broad import (
                kms_key_enclave_pcr_too_broad,
            )

            result = kms_key_enclave_pcr_too_broad().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == key["KeyId"]

    @mock_aws
    def test_malformed_policy_statement_null_does_not_crash(self):
        # Symmetry with Check 8: iterate statements with a null Statement
        # must not crash. The key is in scope via the tag; the malformed
        # statement list yields no attestation → default PASS.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_key(
            kms,
            {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:PCR0": "a" * 96}},
        )

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        kms_svc = KMS(aws_provider)
        for k in kms_svc.keys:
            if k.id == key["KeyId"]:
                k.policy = {"Statement": None}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.kms_client", new=kms_svc),
        ):
            from prowler.providers.aws.services.kms.kms_key_enclave_pcr_too_broad.kms_key_enclave_pcr_too_broad import (
                kms_key_enclave_pcr_too_broad,
            )

            result = kms_key_enclave_pcr_too_broad().execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == key["KeyId"]

    @mock_aws
    def test_wildcard_action_narrow_pcr_fail(self):
        # Action: kms:* expands to include every sensitive action. With only
        # PCR0 binding, Check 9 must FAIL.
        stmt = {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::123456789012:role/enclave-parent"},
            "Action": "kms:*",
            "Resource": "*",
            "Condition": {
                "StringEqualsIgnoreCase": {
                    "kms:RecipientAttestation:PCR0": "a" * 96
                }
            },
        }
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = kms.create_key(
            MultiRegion=False,
            Policy=json.dumps(
                {"Version": "2012-10-17", "Id": "wildcard", "Statement": [stmt]}
            ),
            Tags=[{"TagKey": "prowler:enclave-key", "TagValue": "true"}],
        )["KeyMetadata"]

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.kms_client", new=KMS(aws_provider)),
        ):
            from prowler.providers.aws.services.kms.kms_key_enclave_pcr_too_broad.kms_key_enclave_pcr_too_broad import (
                kms_key_enclave_pcr_too_broad,
            )

            result = kms_key_enclave_pcr_too_broad().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == key["KeyId"]
