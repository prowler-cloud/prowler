import json
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

CHECK_MODULE = (
    "prowler.providers.aws.services.kms.kms_key_enclave_attestation_not_enforced"
    ".kms_key_enclave_attestation_not_enforced"
)


def _policy_with_action(action, condition=None):
    stmt = {
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::123456789012:role/enclave-parent"},
        "Action": action,
        "Resource": "*",
    }
    if condition is not None:
        stmt["Condition"] = condition
    return {
        "Version": "2012-10-17",
        "Id": "enclave-key",
        "Statement": [stmt],
    }


def _create_enclave_tagged_key(kms, policy):
    return kms.create_key(
        MultiRegion=False,
        Policy=json.dumps(policy),
        Tags=[{"TagKey": "prowler:enclave-key", "TagValue": "true"}],
    )["KeyMetadata"]


class Test_kms_key_enclave_attestation_not_enforced:
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
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_not_enforced.kms_key_enclave_attestation_not_enforced import (
                kms_key_enclave_attestation_not_enforced,
            )

            assert kms_key_enclave_attestation_not_enforced().execute() == []

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
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_not_enforced.kms_key_enclave_attestation_not_enforced import (
                kms_key_enclave_attestation_not_enforced,
            )

            assert kms_key_enclave_attestation_not_enforced().execute() == []

    @mock_aws
    def test_enclave_key_with_attestation_pass(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_tagged_key(
            kms,
            _policy_with_action(
                "kms:Decrypt",
                condition={
                    "StringEqualsIgnoreCase": {
                        "kms:RecipientAttestation:PCR0": "abcd" * 24
                    }
                },
            ),
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
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_not_enforced.kms_key_enclave_attestation_not_enforced import (
                kms_key_enclave_attestation_not_enforced,
            )

            result = kms_key_enclave_attestation_not_enforced().execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == key["KeyId"]

    @mock_aws
    def test_enclave_key_without_attestation_fail(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_tagged_key(kms, _policy_with_action("kms:Decrypt"))

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.kms_client", new=KMS(aws_provider)),
        ):
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_not_enforced.kms_key_enclave_attestation_not_enforced import (
                kms_key_enclave_attestation_not_enforced,
            )

            result = kms_key_enclave_attestation_not_enforced().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == key["KeyId"]
            assert "RecipientAttestation" in result[0].status_extended

    @mock_aws
    def test_enclave_key_wildcard_without_attestation_fail(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_tagged_key(kms, _policy_with_action("kms:*"))

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.kms_client", new=KMS(aws_provider)),
        ):
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_not_enforced.kms_key_enclave_attestation_not_enforced import (
                kms_key_enclave_attestation_not_enforced,
            )

            result = kms_key_enclave_attestation_not_enforced().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == key["KeyId"]

    @mock_aws
    def test_enclave_key_via_description_fallback(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = kms.create_key(
            MultiRegion=False,
            Description="production enclave key for the vault workload",
            Policy=json.dumps(_policy_with_action("kms:Decrypt")),
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
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_not_enforced.kms_key_enclave_attestation_not_enforced import (
                kms_key_enclave_attestation_not_enforced,
            )

            result = kms_key_enclave_attestation_not_enforced().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == key["KeyId"]

    @mock_aws
    def test_enclave_key_via_alias_signal_fail(self):
        # No tag, no description hit, no attestation in policy: alias alone
        # must qualify the key so Check 8 catches the missing condition.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = kms.create_key(
            MultiRegion=False,
            Policy=json.dumps(_policy_with_action("kms:Decrypt")),
        )["KeyMetadata"]
        kms.create_alias(
            AliasName="alias/enclave-signing-key", TargetKeyId=key["KeyId"]
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
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_not_enforced.kms_key_enclave_attestation_not_enforced import (
                kms_key_enclave_attestation_not_enforced,
            )

            result = kms_key_enclave_attestation_not_enforced().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == key["KeyId"]

    @mock_aws
    def test_enclave_key_via_policy_attestation_signal_fail(self):
        # No tag, no alias, no description hit. One statement has attestation
        # (triggers Signal 4 for is_enclave_key), another sensitive Allow
        # statement lacks any condition and must FAIL Check 8.
        policy = {
            "Version": "2012-10-17",
            "Id": "mixed-attestation",
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
                            "kms:RecipientAttestation:PCR0": "a" * 96
                        }
                    },
                },
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:role/enclave-parent"
                    },
                    "Action": "kms:GenerateDataKey",
                    "Resource": "*",
                },
            ],
        }
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = kms.create_key(MultiRegion=False, Policy=json.dumps(policy))[
            "KeyMetadata"
        ]

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.kms_client", new=KMS(aws_provider)),
        ):
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_not_enforced.kms_key_enclave_attestation_not_enforced import (
                kms_key_enclave_attestation_not_enforced,
            )

            result = kms_key_enclave_attestation_not_enforced().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == key["KeyId"]
            assert "kms:GenerateDataKey" in result[0].status_extended

    @mock_aws
    def test_action_wildcard_pattern_without_attestation_fail(self):
        # kms:GenerateDataKey* expands to include kms:GenerateDataKey
        # and kms:GenerateDataKeyPair — both sensitive. No attestation → FAIL.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_tagged_key(
            kms, _policy_with_action("kms:GenerateDataKey*")
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
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_not_enforced.kms_key_enclave_attestation_not_enforced import (
                kms_key_enclave_attestation_not_enforced,
            )

            result = kms_key_enclave_attestation_not_enforced().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == key["KeyId"]

    @mock_aws
    def test_action_case_insensitive_without_attestation_fail(self):
        # IAM actions are case-insensitive: "KMS:decrypt" == "kms:Decrypt".
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_tagged_key(kms, _policy_with_action("KMS:decrypt"))

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.kms_client", new=KMS(aws_provider)),
        ):
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_not_enforced.kms_key_enclave_attestation_not_enforced import (
                kms_key_enclave_attestation_not_enforced,
            )

            result = kms_key_enclave_attestation_not_enforced().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == key["KeyId"]

    @mock_aws
    def test_notaction_grants_sensitive_without_attestation_fail(self):
        # NotAction: kms:ListKeys grants everything except ListKeys — includes
        # every sensitive action. No attestation → FAIL.
        stmt = {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::123456789012:role/enclave-parent"},
            "NotAction": "kms:ListKeys",
            "Resource": "*",
        }
        policy = {"Version": "2012-10-17", "Id": "notaction", "Statement": [stmt]}
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = kms.create_key(
            MultiRegion=False,
            Policy=json.dumps(policy),
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
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_not_enforced.kms_key_enclave_attestation_not_enforced import (
                kms_key_enclave_attestation_not_enforced,
            )

            result = kms_key_enclave_attestation_not_enforced().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == key["KeyId"]

    @mock_aws
    def test_stringlike_wildcard_value_treated_as_no_attestation_fail(self):
        # StringLike with value "*" permits any PCR value — not restrictive.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_tagged_key(
            kms,
            _policy_with_action(
                "kms:Decrypt",
                condition={"StringLike": {"kms:RecipientAttestation:PCR0": "*"}},
            ),
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
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_not_enforced.kms_key_enclave_attestation_not_enforced import (
                kms_key_enclave_attestation_not_enforced,
            )

            result = kms_key_enclave_attestation_not_enforced().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == key["KeyId"]

    @mock_aws
    def test_null_operator_treated_as_no_attestation_fail(self):
        # Null: {"...": "true"} means "the key must NOT be present" — inverted.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_tagged_key(
            kms,
            _policy_with_action(
                "kms:Decrypt",
                condition={"Null": {"kms:RecipientAttestation:PCR0": "true"}},
            ),
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
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_not_enforced.kms_key_enclave_attestation_not_enforced import (
                kms_key_enclave_attestation_not_enforced,
            )

            result = kms_key_enclave_attestation_not_enforced().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == key["KeyId"]

    @mock_aws
    def test_stringnotequals_treated_as_no_attestation_fail(self):
        # StringNotEquals inverts the check — permits any value except the
        # listed one. Not restrictive for our purposes.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_tagged_key(
            kms,
            _policy_with_action(
                "kms:Decrypt",
                condition={
                    "StringNotEquals": {"kms:RecipientAttestation:PCR0": "some-value"}
                },
            ),
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
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_not_enforced.kms_key_enclave_attestation_not_enforced import (
                kms_key_enclave_attestation_not_enforced,
            )

            result = kms_key_enclave_attestation_not_enforced().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == key["KeyId"]

    @mock_aws
    def test_stringequalsifexists_treated_as_no_attestation_fail(self):
        # *IfExists passes when the key is not present in the request —
        # allows access without attestation, so not restrictive.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_tagged_key(
            kms,
            _policy_with_action(
                "kms:Decrypt",
                condition={
                    "StringEqualsIfExists": {"kms:RecipientAttestation:PCR0": "a" * 96}
                },
            ),
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
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_not_enforced.kms_key_enclave_attestation_not_enforced import (
                kms_key_enclave_attestation_not_enforced,
            )

            result = kms_key_enclave_attestation_not_enforced().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == key["KeyId"]

    @mock_aws
    def test_malformed_policy_statement_null_does_not_crash(self):
        # A policy with Statement=null (JSON null, Python None) must not
        # crash the check. AWS itself would reject this at submit time, but
        # a corrupted document should still be handled gracefully.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_tagged_key(kms, _policy_with_action("kms:Decrypt"))

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
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_not_enforced.kms_key_enclave_attestation_not_enforced import (
                kms_key_enclave_attestation_not_enforced,
            )

            # Must not raise. The key is in scope via the explicit tag
            # (Signal 1); the malformed statement list is treated as "no
            # offending statements" → default PASS.
            result = kms_key_enclave_attestation_not_enforced().execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == key["KeyId"]

    @mock_aws
    def test_signal_4_guard_against_null_statement(self):
        # Explicitly exercise is_enclave_key's Signal 4 guard: the key must
        # have NO hints from Signals 1/2/3 (no enclave tag, no alias, no
        # "enclave" in description/tags) so the function reaches Signal 4
        # with a policy whose Statement is null. Without the guard, the
        # iteration crashes; with the guard, it returns False and the check
        # skips the key.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = kms.create_key(MultiRegion=False)["KeyMetadata"]

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        kms_svc = KMS(aws_provider)
        for k in kms_svc.keys:
            if k.id == key["KeyId"]:
                k.tags = []
                k.aliases = []
                k.description = ""
                k.policy = {"Statement": None}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.kms_client", new=kms_svc),
        ):
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_not_enforced.kms_key_enclave_attestation_not_enforced import (
                kms_key_enclave_attestation_not_enforced,
            )

            # Must not raise. Key is not an enclave key → skipped → no findings.
            result = kms_key_enclave_attestation_not_enforced().execute()
            assert result == []

    @mock_aws
    def test_partial_wildcard_value_treated_as_no_attestation_fail(self):
        # StringLike with a partial wildcard (`"abc*"`) permits any PCR that
        # starts with "abc". PCR/ImageSha values are fixed hex hashes; wildcard
        # patterns of any shape must not count as a restrictive binding.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_tagged_key(
            kms,
            _policy_with_action(
                "kms:Decrypt",
                condition={"StringLike": {"kms:RecipientAttestation:PCR0": "abc*"}},
            ),
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
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_not_enforced.kms_key_enclave_attestation_not_enforced import (
                kms_key_enclave_attestation_not_enforced,
            )

            result = kms_key_enclave_attestation_not_enforced().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == key["KeyId"]

    @mock_aws
    def test_mixed_case_condition_key_recognized_as_attestation_pass(self):
        # AWS condition keys are case-insensitive. A policy with
        # `KMS:recipientAttestation:PCR0` (mixed case) must still be
        # recognized as an attestation binding → Check 8 PASS.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_tagged_key(
            kms,
            _policy_with_action(
                "kms:Decrypt",
                condition={
                    "StringEqualsIgnoreCase": {
                        "KMS:recipientAttestation:PCR0": "a" * 96
                    }
                },
            ),
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
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_not_enforced.kms_key_enclave_attestation_not_enforced import (
                kms_key_enclave_attestation_not_enforced,
            )

            result = kms_key_enclave_attestation_not_enforced().execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == key["KeyId"]

    @mock_aws
    def test_value_list_with_wildcard_entry_treated_as_no_attestation_fail(self):
        # Any wildcard in a value list disqualifies the whole condition.
        # `[valid_hash, "abc?"]` cannot be trusted as restrictive because
        # the wildcard entry alone permits any 4-char value starting with abc.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_tagged_key(
            kms,
            _policy_with_action(
                "kms:Decrypt",
                condition={
                    "StringEquals": {
                        "kms:RecipientAttestation:PCR0": ["a" * 96, "abc?"]
                    }
                },
            ),
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
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_not_enforced.kms_key_enclave_attestation_not_enforced import (
                kms_key_enclave_attestation_not_enforced,
            )

            result = kms_key_enclave_attestation_not_enforced().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == key["KeyId"]

    @mock_aws
    def test_for_all_values_without_null_guard_treated_as_no_attestation_fail(self):
        # ForAllValues:StringEquals evaluates to true when the request
        # context key is absent. Without a Null:"false" guard, a caller
        # can obtain the sensitive action without providing any attestation.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_tagged_key(
            kms,
            _policy_with_action(
                "kms:Decrypt",
                condition={
                    "ForAllValues:StringEquals": {
                        "kms:RecipientAttestation:PCR0": "a" * 96
                    }
                },
            ),
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
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_not_enforced.kms_key_enclave_attestation_not_enforced import (
                kms_key_enclave_attestation_not_enforced,
            )

            result = kms_key_enclave_attestation_not_enforced().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == key["KeyId"]

    @mock_aws
    def test_for_all_values_with_null_guard_treated_as_attestation_pass(self):
        # Pairing ForAllValues:StringEquals with Null:"false" on the same key
        # forces the caller to send the attestation, restoring restrictive
        # semantics and satisfying the check.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_tagged_key(
            kms,
            _policy_with_action(
                "kms:Decrypt",
                condition={
                    "ForAllValues:StringEquals": {
                        "kms:RecipientAttestation:PCR0": "a" * 96
                    },
                    "Null": {"kms:RecipientAttestation:PCR0": "false"},
                },
            ),
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
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_not_enforced.kms_key_enclave_attestation_not_enforced import (
                kms_key_enclave_attestation_not_enforced,
            )

            result = kms_key_enclave_attestation_not_enforced().execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == key["KeyId"]

    @mock_aws
    def test_for_all_values_null_guard_case_insensitive_key_match_pass(self):
        # The Null guard key uses a different casing than the ForAllValues
        # binding. AWS treats condition keys case-insensitively, so the guard
        # must still cover the binding.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_tagged_key(
            kms,
            _policy_with_action(
                "kms:Decrypt",
                condition={
                    "ForAllValues:StringEquals": {
                        "kms:RecipientAttestation:PCR0": "a" * 96
                    },
                    "Null": {"KMS:recipientattestation:pcr0": "false"},
                },
            ),
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
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_not_enforced.kms_key_enclave_attestation_not_enforced import (
                kms_key_enclave_attestation_not_enforced,
            )

            result = kms_key_enclave_attestation_not_enforced().execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == key["KeyId"]

    @mock_aws
    def test_for_all_values_null_guard_for_different_key_still_fail(self):
        # A Null:false guard on a different attestation key does not rescue
        # the ForAllValues binding — the caller can still omit PCR0 and pass.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_tagged_key(
            kms,
            _policy_with_action(
                "kms:Decrypt",
                condition={
                    "ForAllValues:StringEquals": {
                        "kms:RecipientAttestation:PCR0": "a" * 96
                    },
                    "Null": {"kms:RecipientAttestation:PCR1": "false"},
                },
            ),
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
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_not_enforced.kms_key_enclave_attestation_not_enforced import (
                kms_key_enclave_attestation_not_enforced,
            )

            result = kms_key_enclave_attestation_not_enforced().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == key["KeyId"]

    @mock_aws
    def test_policy_fetch_error_reports_manual(self):
        # Simulate a GetKeyPolicy failure and confirm the check emits MANUAL
        # (fail-closed on missing visibility) instead of silently skipping.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_tagged_key(
            kms,
            _policy_with_action("kms:Decrypt"),
        )

        from prowler.providers.aws.services.kms.kms_service import KMS

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
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_not_enforced.kms_key_enclave_attestation_not_enforced import (
                kms_key_enclave_attestation_not_enforced,
            )

            result = kms_key_enclave_attestation_not_enforced().execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "policy could not be fetched" in result[0].status_extended
            assert "AccessDeniedException" in result[0].status_extended
