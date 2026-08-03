import json
from datetime import datetime, timezone
from unittest import mock

from prowler.providers.aws.services.kms.lib.enclave import SENSITIVE_ENCLAVE_KMS_EVENTS
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CHECK_MODULE = (
    "prowler.providers.aws.services.kms.kms_key_enclave_debug_attestation_detected"
    ".kms_key_enclave_debug_attestation_detected"
)

REAL_PCR = "a" * 96
ZERO_PCR = "0" * 96
KEY_ARN_A = f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
KEY_ARN_B = f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
INSTANCE_ID = "i-0123456789abcdef0"


def _mock_trail(is_multiregion=True):
    trail = mock.MagicMock()
    trail.is_multiregion = is_multiregion
    trail.region = AWS_REGION_US_EAST_1
    return trail


def _mock_key(arn):
    k = mock.MagicMock()
    k.arn = arn
    k.id = arn.rsplit("/", 1)[-1]
    k.region = AWS_REGION_US_EAST_1
    k.tags = []
    return k


def _event(key_arn, event_name, debug=False, event_time=None, instance_id=INSTANCE_ID):
    value = ZERO_PCR if debug else REAL_PCR
    recipient = {
        "attestationDocumentModuleId": f"{instance_id}-enc9876abcd543210ef12",
        "attestationDocumentEnclaveImageDigest": value,
        "attestationDocumentEnclavePCR1": value,
        "attestationDocumentEnclavePCR2": value,
        "attestationDocumentEnclavePCR3": value,
        "attestationDocumentEnclavePCR4": value,
        "attestationDocumentEnclavePCR8": value,
    }
    payload = {
        "eventName": event_name,
        "eventSource": "kms.amazonaws.com",
        "additionalEventData": {"recipient": recipient},
        "resources": [
            {"accountId": AWS_ACCOUNT_NUMBER, "type": "AWS::KMS::Key", "ARN": key_arn}
        ],
    }
    return {
        "EventTime": event_time or datetime(2026, 7, 14, 12, 0, tzinfo=timezone.utc),
        "CloudTrailEvent": json.dumps(payload),
        "Resources": [{"ResourceType": "AWS::KMS::Key", "ResourceName": key_arn}],
    }


def _run(
    events_by_event_name=None,
    trails=None,
    truncated=False,
    audit_config=None,
    keys=None,
    regions=None,
    lookup_error=None,
):
    kms_client = mock.MagicMock()
    kms_client.keys = keys or []
    kms_client.audit_config = audit_config or {}
    kms_client.audited_account = AWS_ACCOUNT_NUMBER
    kms_client.region = AWS_REGION_US_EAST_1

    cloudtrail_client = mock.MagicMock()
    if trails is None:
        cloudtrail_client.trails = {"t": _mock_trail(is_multiregion=True)}
    else:
        cloudtrail_client.trails = trails
    # Regions the check will iterate; default to a single region so each event
    # is delivered exactly once (multi-region setup adds a separate test).
    cloudtrail_client.regional_clients = {
        r: mock.MagicMock() for r in (regions or [AWS_REGION_US_EAST_1])
    }

    def _lookup(region, event_name, minutes):
        if lookup_error is not None:
            return [], False, lookup_error
        return (events_by_event_name or {}).get(event_name, []), truncated, None

    cloudtrail_client._lookup_events_page = _lookup

    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ),
        mock.patch(f"{CHECK_MODULE}.kms_client", new=kms_client),
        mock.patch(f"{CHECK_MODULE}.cloudtrail_client", new=cloudtrail_client),
    ):
        from prowler.providers.aws.services.kms.kms_key_enclave_debug_attestation_detected.kms_key_enclave_debug_attestation_detected import (
            kms_key_enclave_debug_attestation_detected,
        )

        return kms_key_enclave_debug_attestation_detected().execute()


class Test_kms_key_enclave_debug_attestation_detected:
    def test_no_trails_no_keys_returns_single_manual(self):
        result = _run(trails={})
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "No CloudTrail trails" in result[0].status_extended

    def test_no_trails_with_target_key_reports_manual_per_key(self):
        result = _run(
            trails={},
            keys=[_mock_key(KEY_ARN_A)],
            audit_config={
                "enclave_debug_target_key_ids": [KEY_ARN_A.rsplit("/", 1)[-1]]
            },
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert KEY_ARN_A in result[0].status_extended

    def test_no_events_reports_manual_account_scope(self):
        result = _run(events_by_event_name={})
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "No KMS-from-enclave attestation events" in result[0].status_extended

    def test_debug_event_against_key_reports_fail(self):
        result = _run(
            events_by_event_name={
                "Decrypt": [_event(KEY_ARN_A, "Decrypt", debug=True)]
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert KEY_ARN_A in result[0].status_extended
        assert "PCR0/1/2 are zeroed" in result[0].status_extended

    def test_legit_event_only_reports_pass(self):
        result = _run(
            events_by_event_name={
                "GenerateDataKey": [_event(KEY_ARN_A, "GenerateDataKey", debug=False)]
            },
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "none carry zeroed PCR0/1/2" in result[0].status_extended

    def test_mixed_events_any_debug_reports_fail(self):
        result = _run(
            events_by_event_name={
                "Decrypt": [
                    _event(KEY_ARN_A, "Decrypt", debug=False),
                    _event(KEY_ARN_A, "Decrypt", debug=True),
                ]
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_truncated_page_no_debug_reports_manual_coverage_limited(self):
        result = _run(
            events_by_event_name={
                "Decrypt": [_event(KEY_ARN_A, "Decrypt", debug=False)]
            },
            truncated=True,
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "event cap" in result[0].status_extended

    def test_truncated_page_with_debug_still_fails(self):
        result = _run(
            events_by_event_name={
                "Decrypt": [_event(KEY_ARN_A, "Decrypt", debug=True)]
            },
            truncated=True,
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_multiple_keys_per_key_verdicts(self):
        events = {
            "Decrypt": [
                _event(KEY_ARN_A, "Decrypt", debug=True),
                _event(KEY_ARN_B, "Decrypt", debug=False),
            ]
        }
        result = _run(events_by_event_name=events)
        by_arn = {r.resource_arn: r.status for r in result}
        assert by_arn[KEY_ARN_A] == "FAIL"
        assert by_arn[KEY_ARN_B] == "PASS"

    def test_target_key_filter_narrows_reports(self):
        events = {
            "Decrypt": [
                _event(KEY_ARN_A, "Decrypt", debug=True),
                _event(KEY_ARN_B, "Decrypt", debug=True),
            ]
        }
        result = _run(
            events_by_event_name=events,
            audit_config={
                "enclave_debug_target_key_ids": [KEY_ARN_A.rsplit("/", 1)[-1]]
            },
        )
        arns = {r.resource_arn for r in result}
        assert arns == {KEY_ARN_A}

    def test_target_key_configured_no_events_but_key_known_reports_per_key_manual(self):
        result = _run(
            events_by_event_name={},
            audit_config={
                "enclave_debug_target_key_ids": [KEY_ARN_A.rsplit("/", 1)[-1]]
            },
            keys=[_mock_key(KEY_ARN_A)],
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_arn == KEY_ARN_A

    def test_custom_lookback_window_flows_through(self):
        captured = {}

        def _lookup(region, event_name, minutes):
            captured["minutes"] = minutes
            return [], False, None

        kms_client = mock.MagicMock()
        kms_client.keys = []
        kms_client.audit_config = {"enclave_debug_lookback_window_hours": 6}
        kms_client.audited_account = AWS_ACCOUNT_NUMBER
        kms_client.region = AWS_REGION_US_EAST_1
        cloudtrail_client = mock.MagicMock()
        cloudtrail_client.trails = {"t": _mock_trail(is_multiregion=True)}
        cloudtrail_client.regional_clients = {AWS_REGION_US_EAST_1: mock.MagicMock()}
        cloudtrail_client._lookup_events_page = _lookup

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(f"{CHECK_MODULE}.kms_client", new=kms_client),
            mock.patch(f"{CHECK_MODULE}.cloudtrail_client", new=cloudtrail_client),
        ):
            from prowler.providers.aws.services.kms.kms_key_enclave_debug_attestation_detected.kms_key_enclave_debug_attestation_detected import (
                kms_key_enclave_debug_attestation_detected,
            )

            kms_key_enclave_debug_attestation_detected().execute()

        assert captured["minutes"] == 6 * 60

    def test_event_without_key_arn_is_dropped(self):
        raw = {
            "EventTime": datetime(2026, 7, 14, tzinfo=timezone.utc),
            "CloudTrailEvent": json.dumps(
                {
                    "eventName": "Decrypt",
                    "additionalEventData": {
                        "recipient": {
                            "attestationDocumentModuleId": f"{INSTANCE_ID}-enc9876abcd543210ef12",
                            "attestationDocumentEnclaveImageDigest": ZERO_PCR,
                        }
                    },
                }
            ),
        }
        result = _run(events_by_event_name={"Decrypt": [raw]})
        assert len(result) == 1
        assert result[0].status == "MANUAL"

    def test_malformed_event_dropped(self):
        result = _run(
            events_by_event_name={"Decrypt": [{"CloudTrailEvent": "not-json"}]}
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"

    def test_partial_zero_pcrs_not_flagged_as_debug(self):
        recipient = {
            "attestationDocumentModuleId": f"{INSTANCE_ID}-enc9876abcd543210ef12",
            "attestationDocumentEnclaveImageDigest": ZERO_PCR,
            "attestationDocumentEnclavePCR1": REAL_PCR,
        }
        payload = {
            "eventName": "Decrypt",
            "additionalEventData": {"recipient": recipient},
            "resources": [
                {
                    "accountId": AWS_ACCOUNT_NUMBER,
                    "type": "AWS::KMS::Key",
                    "ARN": KEY_ARN_A,
                }
            ],
        }
        raw = {
            "EventTime": datetime(2026, 7, 14, tzinfo=timezone.utc),
            "CloudTrailEvent": json.dumps(payload),
        }
        result = _run(events_by_event_name={"Decrypt": [raw]})
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_single_zero_pcr_field_alone_not_debug(self):
        # Per RFC v2.6 debug enclaves have ALL PCRs zero; a single zero PCR
        # field with the rest absent is treated as truncated/malformed, not
        # as debug-mode evidence.
        recipient = {
            "attestationDocumentModuleId": f"{INSTANCE_ID}-enc9876abcd543210ef12",
            "attestationDocumentEnclavePCR1": ZERO_PCR,
        }
        payload = {
            "eventName": "Decrypt",
            "additionalEventData": {"recipient": recipient},
            "resources": [
                {
                    "accountId": AWS_ACCOUNT_NUMBER,
                    "type": "AWS::KMS::Key",
                    "ARN": KEY_ARN_A,
                }
            ],
        }
        raw = {
            "EventTime": datetime(2026, 7, 14, tzinfo=timezone.utc),
            "CloudTrailEvent": json.dumps(payload),
        }
        result = _run(events_by_event_name={"Decrypt": [raw]})
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_event_for_non_kms_resource_ignored(self):
        payload = {
            "eventName": "Decrypt",
            "additionalEventData": {
                "recipient": {
                    "attestationDocumentModuleId": f"{INSTANCE_ID}-enc9876abcd543210ef12",
                    "attestationDocumentEnclaveImageDigest": ZERO_PCR,
                }
            },
            "resources": [{"type": "AWS::S3::Bucket", "ARN": "arn:aws:s3:::my-bucket"}],
        }
        raw = {
            "EventTime": datetime(2026, 7, 14, tzinfo=timezone.utc),
            "CloudTrailEvent": json.dumps(payload),
        }
        result = _run(events_by_event_name={"Decrypt": [raw]})
        assert len(result) == 1
        assert result[0].status == "MANUAL"

    def test_multiple_events_against_same_key_aggregate(self):
        events = {
            "Decrypt": [
                _event(KEY_ARN_A, "Decrypt", debug=False),
                _event(KEY_ARN_A, "Decrypt", debug=False),
                _event(KEY_ARN_A, "Decrypt", debug=False),
            ]
        }
        result = _run(events_by_event_name=events)
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "3 enclave attestation events" in result[0].status_extended

    def test_multi_region_iterates_every_region(self):
        # LookupEvents is per-region even for multi-region trails; the check
        # must iterate every regional client, not just the trail's home region.
        calls_per_region = {}

        def _lookup(region, event_name, minutes):
            calls_per_region.setdefault(region, 0)
            calls_per_region[region] += 1
            return [], False, None

        cloudtrail_client = mock.MagicMock()
        cloudtrail_client.trails = {"t": _mock_trail(is_multiregion=True)}
        cloudtrail_client.regional_clients = {
            "us-east-1": mock.MagicMock(),
            "eu-west-1": mock.MagicMock(),
            "ap-south-1": mock.MagicMock(),
        }
        cloudtrail_client._lookup_events_page = _lookup

        kms_client = mock.MagicMock()
        kms_client.keys = []
        kms_client.audit_config = {}
        kms_client.audited_account = AWS_ACCOUNT_NUMBER
        kms_client.region = AWS_REGION_US_EAST_1

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(f"{CHECK_MODULE}.kms_client", new=kms_client),
            mock.patch(f"{CHECK_MODULE}.cloudtrail_client", new=cloudtrail_client),
        ):
            from prowler.providers.aws.services.kms.kms_key_enclave_debug_attestation_detected.kms_key_enclave_debug_attestation_detected import (
                kms_key_enclave_debug_attestation_detected,
            )

            kms_key_enclave_debug_attestation_detected().execute()

        # Every region hit once per sensitive event name (5 event names:
        # Decrypt, DeriveSharedSecret, GenerateDataKey, GenerateDataKeyPair,
        # GenerateRandom).
        assert set(calls_per_region.keys()) == {"us-east-1", "eu-west-1", "ap-south-1"}
        assert all(
            v == len(SENSITIVE_ENCLAVE_KMS_EVENTS) for v in calls_per_region.values()
        )

    def test_lookup_error_reported_as_incomplete_coverage(self):
        result = _run(
            events_by_event_name={},
            lookup_error="AccessDeniedException",
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "CloudTrail lookup failed" in result[0].status_extended
        assert "AccessDeniedException" in result[0].status_extended
        assert "Coverage is incomplete" in result[0].status_extended

    def test_recipient_missing_or_non_dict_dropped(self):
        # additionalEventData without a recipient block, or recipient as a
        # string / list, should be treated as non-relevant (parsed=None), not
        # raise. Verify by running one event with each malformed shape.
        malformed = []
        for bad_recipient in (None, "not-a-dict", ["list"], 42):
            payload = {
                "eventName": "Decrypt",
                "additionalEventData": {"recipient": bad_recipient},
                "resources": [
                    {
                        "accountId": AWS_ACCOUNT_NUMBER,
                        "type": "AWS::KMS::Key",
                        "ARN": KEY_ARN_A,
                    }
                ],
            }
            malformed.append(
                {
                    "EventTime": datetime(2026, 7, 14, tzinfo=timezone.utc),
                    "CloudTrailEvent": json.dumps(payload),
                }
            )
        result = _run(events_by_event_name={"Decrypt": malformed})
        # All events dropped → no per-key finding, single synthetic MANUAL.
        assert len(result) == 1
        assert result[0].status == "MANUAL"

    def test_missing_module_id_dropped(self):
        # A recipient without attestationDocumentModuleId (or without "-enc")
        # should be treated as non-enclave and dropped by parse_enclave_kms_event.
        payload = {
            "eventName": "Decrypt",
            "additionalEventData": {
                "recipient": {
                    "attestationDocumentEnclaveImageDigest": ZERO_PCR,
                    "attestationDocumentEnclavePCR1": ZERO_PCR,
                    "attestationDocumentEnclavePCR2": ZERO_PCR,
                    "attestationDocumentEnclavePCR3": ZERO_PCR,
                    "attestationDocumentEnclavePCR4": ZERO_PCR,
                    "attestationDocumentEnclavePCR8": ZERO_PCR,
                    # attestationDocumentModuleId intentionally missing
                }
            },
            "resources": [
                {
                    "accountId": AWS_ACCOUNT_NUMBER,
                    "type": "AWS::KMS::Key",
                    "ARN": KEY_ARN_A,
                }
            ],
        }
        raw = {
            "EventTime": datetime(2026, 7, 14, tzinfo=timezone.utc),
            "CloudTrailEvent": json.dumps(payload),
        }
        result = _run(events_by_event_name={"Decrypt": [raw]})
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "No KMS-from-enclave" in result[0].status_extended


# Base64 encoding of a SHA384 hash (48 bytes = 64 base64 chars). CloudTrail
# records PCR values in this format, hex is only used by nitro-cli / audit_config.
ZERO_PCR_BASE64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
REAL_PCR_BASE64 = "COlmS551s/ZEgeUQiSsr24Q7IqoXj7rGPsUqOgSwOGls4xRcsJbdf30qxcdSL0OP"


class Test_debug_attestation_base64_encoding:
    """Reality: CloudTrail returns PCR values in base64, not hex.
    These tests protect against regressing to the hex-only bug caught in playground.
    """

    def test_base64_all_zero_recipient_detected_as_debug(self):
        # A real debug enclave in CloudTrail shows all 6 fields as
        # "AAAA..." (64 chars base64 of zero bytes).
        from prowler.providers.aws.services.kms.lib.enclave import (
            is_debug_attestation,
        )

        recipient = {
            "attestationDocumentModuleId": f"{INSTANCE_ID}-enc9876abcd543210ef12",
            "attestationDocumentEnclaveImageDigest": ZERO_PCR_BASE64,
            "attestationDocumentEnclavePCR1": ZERO_PCR_BASE64,
            "attestationDocumentEnclavePCR2": ZERO_PCR_BASE64,
            "attestationDocumentEnclavePCR3": ZERO_PCR_BASE64,
            "attestationDocumentEnclavePCR4": ZERO_PCR_BASE64,
            "attestationDocumentEnclavePCR8": ZERO_PCR_BASE64,
        }
        assert is_debug_attestation(recipient) is True

    def test_base64_real_recipient_not_debug(self):
        from prowler.providers.aws.services.kms.lib.enclave import (
            is_debug_attestation,
        )

        recipient = {
            "attestationDocumentModuleId": f"{INSTANCE_ID}-enc9876abcd543210ef12",
            "attestationDocumentEnclaveImageDigest": REAL_PCR_BASE64,
            "attestationDocumentEnclavePCR1": REAL_PCR_BASE64,
            "attestationDocumentEnclavePCR2": REAL_PCR_BASE64,
            "attestationDocumentEnclavePCR3": REAL_PCR_BASE64,
            "attestationDocumentEnclavePCR4": REAL_PCR_BASE64,
            "attestationDocumentEnclavePCR8": REAL_PCR_BASE64,
        }
        assert is_debug_attestation(recipient) is False

    def test_base64_extract_pcrs_yields_canonical_hex(self):
        # extract_pcrs_from_recipient should decode base64 and re-render as hex
        # so downstream comparisons work regardless of input encoding.
        from prowler.providers.aws.services.kms.lib.enclave import (
            extract_pcrs_from_recipient,
        )

        recipient = {
            "attestationDocumentEnclaveImageDigest": REAL_PCR_BASE64,
        }
        result = extract_pcrs_from_recipient(recipient)
        # Should be lowercase hex, 96 chars.
        assert "PCR0" in result
        assert len(result["PCR0"]) == 96
        assert result["PCR0"] == result["PCR0"].lower()
        # And it should equal the hex form of the same bytes
        import base64

        assert result["PCR0"] == base64.b64decode(REAL_PCR_BASE64).hex()

    def test_unknown_pcrs_cross_encoding_hex_golden_vs_base64_observed(self):
        # The playground scenario: user configures golden in hex (from
        # nitro-cli describe-eif), CloudTrail returns base64. They must match.
        import base64

        from prowler.providers.aws.services.kms.lib.enclave import (
            unknown_pcrs,
        )

        real_hex = base64.b64decode(REAL_PCR_BASE64).hex()
        observed = {"PCR0": real_hex}  # already canonicalized to hex
        golden = {"PCR0": {real_hex}}  # user provided hex
        assert unknown_pcrs(observed, golden) == {}

        # And if observed doesn't match golden → flagged.
        other_hex = "b" * 96
        observed = {"PCR0": other_hex}
        assert unknown_pcrs(observed, golden) == {"PCR0": other_hex}
