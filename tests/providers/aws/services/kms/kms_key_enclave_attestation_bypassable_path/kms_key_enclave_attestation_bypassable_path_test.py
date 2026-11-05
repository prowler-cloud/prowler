import json
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

CHECK_MODULE = (
    "prowler.providers.aws.services.kms.kms_key_enclave_attestation_bypassable_path"
    ".kms_key_enclave_attestation_bypassable_path"
)

PCR0 = "a" * 96
ROOT = "arn:aws:iam::123456789012:root"


def _policy(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def _allow_sensitive_with_attestation(sid="Enc"):
    return {
        "Sid": sid,
        "Effect": "Allow",
        "Principal": {"AWS": ROOT},
        "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
        "Resource": "*",
        "Condition": {
            "StringEqualsIgnoreCase": {"kms:RecipientAttestation:PCR0": PCR0}
        },
    }


def _allow_sensitive_no_condition(sid="NoAtt", action="kms:Decrypt"):
    return {
        "Sid": sid,
        "Effect": "Allow",
        "Principal": {"AWS": ROOT},
        "Action": action,
        "Resource": "*",
    }


def _root_admin_wildcard():
    return {
        "Sid": "RootAdminAllData",
        "Effect": "Allow",
        "Principal": {"AWS": ROOT},
        "Action": "kms:*",
        "Resource": "*",
    }


def _admin_no_data():
    return {
        "Sid": "AdminNoDataActions",
        "Effect": "Allow",
        "Principal": {"AWS": ROOT},
        "Action": ["kms:Describe*", "kms:List*", "kms:Get*"],
        "Resource": "*",
    }


def _deny_when_attestation_absent(actions=None):
    return {
        "Sid": "DenyIfNoAtt",
        "Effect": "Deny",
        "Principal": "*",
        "Action": actions
        or [
            "kms:Decrypt",
            "kms:GenerateDataKey",
            "kms:GenerateDataKeyPair",
            "kms:GenerateRandom",
        ],
        "Resource": "*",
        "Condition": {"Null": {"kms:RecipientAttestation:PCR0": "true"}},
    }


def _deny_no_attest_condition():
    return {
        "Sid": "DenyDecrypt",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "kms:Decrypt",
        "Resource": "*",
    }


def _create_enclave_key(kms, policy):
    return kms.create_key(
        MultiRegion=False,
        Policy=json.dumps(policy),
        Tags=[{"TagKey": "prowler:enclave-key", "TagValue": "true"}],
    )["KeyMetadata"]


def _run():
    from prowler.providers.aws.services.kms.kms_service import KMS

    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(f"{CHECK_MODULE}.kms_client", new=KMS(aws_provider)),
    ):
        from prowler.providers.aws.services.kms.kms_key_enclave_attestation_bypassable_path.kms_key_enclave_attestation_bypassable_path import (
            kms_key_enclave_attestation_bypassable_path,
        )

        return kms_key_enclave_attestation_bypassable_path().execute()


class Test_kms_key_enclave_attestation_bypassable_path:
    @mock_aws
    def test_no_keys_returns_empty(self):
        assert _run() == []

    @mock_aws
    def test_non_enclave_key_skipped(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        kms.create_key(MultiRegion=False)
        assert _run() == []

    @mock_aws
    def test_empty_statement_list_passes(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        _create_enclave_key(kms, _policy())
        result = _run()
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_all_sensitive_allows_have_attestation_pass(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        _create_enclave_key(
            kms, _policy(_admin_no_data(), _allow_sensitive_with_attestation())
        )
        result = _run()
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_sensitive_allow_without_attestation_fail(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        _create_enclave_key(kms, _policy(_allow_sensitive_no_condition()))
        result = _run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "NoAtt" in result[0].status_extended
        assert "bypass path" in result[0].status_extended

    @mock_aws
    def test_root_delegation_kms_wildcard_fail(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        _create_enclave_key(kms, _policy(_root_admin_wildcard()))
        result = _run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "RootAdminAllData" in result[0].status_extended

    @mock_aws
    def test_root_delegation_kms_wildcard_with_attestation_pass(self):
        # kms:* with attestation condition → no bypass
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        stmt = _root_admin_wildcard()
        stmt["Condition"] = {
            "StringEqualsIgnoreCase": {"kms:RecipientAttestation:PCR0": PCR0}
        }
        _create_enclave_key(kms, _policy(stmt))
        result = _run()
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_two_allows_one_with_attestation_one_without_fail(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        _create_enclave_key(
            kms,
            _policy(
                _allow_sensitive_with_attestation(sid="Enc"),
                _allow_sensitive_no_condition(sid="Backdoor"),
            ),
        )
        result = _run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "Backdoor" in result[0].status_extended

    @mock_aws
    def test_allow_without_attestation_but_deny_null_covers_pass(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        _create_enclave_key(
            kms,
            _policy(
                _allow_sensitive_no_condition(),
                _deny_when_attestation_absent(),
            ),
        )
        result = _run()
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_allow_decrypt_deny_decrypt_missing_attestation_pass(self):
        # The Allow grants only kms:Decrypt and the Deny neutralises exactly
        # that action when attestation is absent, so the sensitive-action
        # coverage set matches and the finding is PASS.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        _create_enclave_key(
            kms,
            _policy(
                _allow_sensitive_no_condition(),  # grants Decrypt only
                _deny_when_attestation_absent(actions=["kms:Decrypt"]),
            ),
        )
        result = _run()
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_deny_missing_attestation_condition_fail(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        _create_enclave_key(
            kms,
            _policy(
                _allow_sensitive_no_condition(),
                _deny_no_attest_condition(),
            ),
        )
        result = _run()
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_deny_string_not_equals_if_exists_covers_pass(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        deny_stmt = {
            "Sid": "DenyOnMismatch",
            "Effect": "Deny",
            "Principal": "*",
            "Action": [
                "kms:Decrypt",
                "kms:GenerateDataKey",
                "kms:GenerateDataKeyPair",
                "kms:GenerateRandom",
            ],
            "Resource": "*",
            "Condition": {
                "StringNotEqualsIfExists": {"kms:RecipientAttestation:PCR0": PCR0}
            },
        }
        _create_enclave_key(kms, _policy(_allow_sensitive_no_condition(), deny_stmt))
        result = _run()
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_not_action_excluding_only_non_sensitive_fail(self):
        # NotAction excludes only kms:ListKeys → Allow grants everything else,
        # including sensitive actions, without any attestation condition.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        stmt = {
            "Sid": "AllExceptList",
            "Effect": "Allow",
            "Principal": {"AWS": ROOT},
            "NotAction": ["kms:ListKeys"],
            "Resource": "*",
        }
        _create_enclave_key(kms, _policy(stmt))
        result = _run()
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_only_non_sensitive_actions_pass(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        _create_enclave_key(kms, _policy(_admin_no_data()))
        result = _run()
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_deny_sensitive_without_conditions_passes(self):
        # A statement with Effect=Deny on sensitive actions is not itself a
        # bypass path (Deny is restrictive by nature). No Allow → PASS.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        _create_enclave_key(kms, _policy(_deny_no_attest_condition()))
        result = _run()
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_case_insensitive_action_kms_decrypt_lowercased_fail(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        stmt = _allow_sensitive_no_condition(action="kms:decrypt")
        _create_enclave_key(kms, _policy(stmt))
        result = _run()
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_statement_as_dict_not_list_parsed(self):
        # Policy with a single statement expressed as a dict (not a list).
        # Mocked directly because moto is strict about Statement shape.
        key = mock.MagicMock()
        key.manager = "CUSTOMER"
        key.state = "Enabled"
        key.policy = {
            "Version": "2012-10-17",
            "Statement": _allow_sensitive_no_condition(),
        }
        key.tags = [{"TagKey": "prowler:enclave-key", "TagValue": "true"}]
        key.id = "single-stmt-dict-key"
        key.arn = (
            f"arn:aws:kms:{AWS_REGION_US_EAST_1}:123456789012:key/single-stmt-dict-key"
        )
        key.region = AWS_REGION_US_EAST_1
        client_mock = mock.MagicMock()
        client_mock.keys = [key]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
            ),
            mock.patch(f"{CHECK_MODULE}.kms_client", new=client_mock),
        ):
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_bypassable_path.kms_key_enclave_attestation_bypassable_path import (
                kms_key_enclave_attestation_bypassable_path,
            )

            result = kms_key_enclave_attestation_bypassable_path().execute()
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_malformed_statement_null_does_not_crash(self):
        # Injecting non-dict statements should be silently skipped.
        key = mock.MagicMock()
        key.manager = "CUSTOMER"
        key.state = "Enabled"
        key.policy = {
            "Version": "2012-10-17",
            "Statement": [None, "not a dict", _allow_sensitive_with_attestation()],
        }
        key.tags = [{"TagKey": "prowler:enclave-key", "TagValue": "true"}]
        key.id = "malformed-key"
        key.arn = f"arn:aws:kms:{AWS_REGION_US_EAST_1}:123456789012:key/malformed-key"
        key.region = AWS_REGION_US_EAST_1
        client_mock = mock.MagicMock()
        client_mock.keys = [key]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
            ),
            mock.patch(f"{CHECK_MODULE}.kms_client", new=client_mock),
        ):
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_bypassable_path.kms_key_enclave_attestation_bypassable_path import (
                kms_key_enclave_attestation_bypassable_path,
            )

            result = kms_key_enclave_attestation_bypassable_path().execute()
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_deny_with_not_action_excluding_only_non_sensitive_covers_pass(self):
        # Deny with NotAction:["kms:ListKeys"] denies every action except
        # ListKeys → covers Decrypt/GenerateDataKey/etc. Paired with
        # Null:true on RecipientAttestation, this DOES neutralize the Allow.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        deny = {
            "Sid": "DenyAllExceptListNoAtt",
            "Effect": "Deny",
            "Principal": "*",
            "NotAction": ["kms:ListKeys"],
            "Resource": "*",
            "Condition": {"Null": {"kms:RecipientAttestation:PCR0": "true"}},
        }
        _create_enclave_key(kms, _policy(_allow_sensitive_no_condition(), deny))
        result = _run()
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_deny_with_not_action_that_excludes_sensitive_action_fail(self):
        # Deny with NotAction:["kms:Decrypt"] → does NOT deny Decrypt →
        # cannot cover an Allow that granted Decrypt.
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        deny = {
            "Sid": "DenyEverythingExceptDecrypt",
            "Effect": "Deny",
            "Principal": "*",
            "NotAction": ["kms:Decrypt"],
            "Resource": "*",
            "Condition": {"Null": {"kms:RecipientAttestation:PCR0": "true"}},
        }
        _create_enclave_key(
            kms, _policy(_allow_sensitive_no_condition(action="kms:Decrypt"), deny)
        )
        result = _run()
        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_disabled_key_skipped(self):
        kms = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = _create_enclave_key(kms, _policy(_allow_sensitive_no_condition()))
        kms.disable_key(KeyId=key["KeyId"])
        assert _run() == []

    @mock_aws
    def test_deny_with_string_not_equals_ignore_case_if_exists_covers(self):
        # Documented restrictive Deny operator variant that should neutralize
        # a sensitive unconditioned Allow.
        policy = {
            "Version": "2012-10-17",
            "Id": "enclave-key",
            "Statement": [
                {
                    "Sid": "RootAllData",
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                },
                {
                    "Sid": "DenyWithoutAttestation",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                    "Condition": {
                        "StringNotEqualsIgnoreCaseIfExists": {
                            "kms:RecipientAttestation:PCR0": "a" * 96
                        }
                    },
                },
            ],
        }
        kms_native = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = kms_native.create_key(
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
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_bypassable_path.kms_key_enclave_attestation_bypassable_path import (
                kms_key_enclave_attestation_bypassable_path,
            )

            result = kms_key_enclave_attestation_bypassable_path().execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == key["KeyId"]

    @mock_aws
    def test_deny_with_not_principal_does_not_cover(self):
        # Documented limitation: Deny statements using NotPrincipal are not
        # recognized as neutralizing the sensitive Allow. Verify fail-closed.
        policy = {
            "Version": "2012-10-17",
            "Id": "enclave-key",
            "Statement": [
                {
                    "Sid": "RootAllData",
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                },
                {
                    "Sid": "DenyNotPrincipal",
                    "Effect": "Deny",
                    "NotPrincipal": {"AWS": "arn:aws:iam::123456789012:role/enclave"},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                    "Condition": {"Null": {"kms:RecipientAttestation:PCR0": "true"}},
                },
            ],
        }
        kms_native = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = kms_native.create_key(
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
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_bypassable_path.kms_key_enclave_attestation_bypassable_path import (
                kms_key_enclave_attestation_bypassable_path,
            )

            result = kms_key_enclave_attestation_bypassable_path().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == key["KeyId"]
