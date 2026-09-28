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
    "prowler.providers.aws.services.kms.kms_key_enclave_attestation_unknown_image"
    ".kms_key_enclave_attestation_unknown_image"
)

GOLDEN_PCR0 = "a" * 96
GOLDEN_PCR1 = "b" * 96
UNKNOWN_PCR0 = "c" * 96
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


def _event(
    key_arn,
    event_name="Decrypt",
    pcr0=GOLDEN_PCR0,
    pcr1=GOLDEN_PCR1,
    debug=False,
    event_time=None,
    instance_id=INSTANCE_ID,
):
    if debug:
        # Real debug enclave produces all-zeros across every PCR field.
        recipient = {
            "attestationDocumentModuleId": f"{instance_id}-enc9876abcd543210ef12",
            "attestationDocumentEnclaveImageDigest": ZERO_PCR,
            "attestationDocumentEnclavePCR1": ZERO_PCR,
            "attestationDocumentEnclavePCR2": ZERO_PCR,
            "attestationDocumentEnclavePCR3": ZERO_PCR,
            "attestationDocumentEnclavePCR4": ZERO_PCR,
            "attestationDocumentEnclavePCR8": ZERO_PCR,
        }
    else:
        recipient = {
            "attestationDocumentModuleId": f"{instance_id}-enc9876abcd543210ef12",
            "attestationDocumentEnclaveImageDigest": pcr0,
            "attestationDocumentEnclavePCR1": pcr1,
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
        "EventTime": event_time or datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc),
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
        from prowler.providers.aws.services.kms.kms_key_enclave_attestation_unknown_image.kms_key_enclave_attestation_unknown_image import (
            kms_key_enclave_attestation_unknown_image,
        )

        return kms_key_enclave_attestation_unknown_image().execute()


class Test_kms_key_enclave_attestation_unknown_image:
    def test_no_golden_config_reports_manual(self):
        result = _run(events_by_event_name={"Decrypt": [_event(KEY_ARN_A)]})
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "enclave_golden_pcr_values" in result[0].status_extended

    def test_no_trails_reports_manual(self):
        result = _run(
            trails={},
            audit_config={"enclave_golden_pcr_values": {"PCR0": [GOLDEN_PCR0]}},
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "No CloudTrail trails" in result[0].status_extended

    def test_no_events_reports_manual(self):
        result = _run(
            events_by_event_name={},
            audit_config={"enclave_golden_pcr_values": {"PCR0": [GOLDEN_PCR0]}},
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "No non-debug attestation events" in result[0].status_extended

    def test_events_all_known_pcrs_pass(self):
        result = _run(
            events_by_event_name={"Decrypt": [_event(KEY_ARN_A)]},
            audit_config={
                "enclave_golden_pcr_values": {
                    "PCR0": [GOLDEN_PCR0],
                    "PCR1": [GOLDEN_PCR1],
                }
            },
        )
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_unknown_pcr_reports_fail(self):
        result = _run(
            events_by_event_name={"Decrypt": [_event(KEY_ARN_A, pcr0=UNKNOWN_PCR0)]},
            audit_config={"enclave_golden_pcr_values": {"PCR0": [GOLDEN_PCR0]}},
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "PCR0" in result[0].status_extended
        assert UNKNOWN_PCR0 in result[0].status_extended
        assert result[0].check_metadata.Severity.value == "medium"  # default

    def test_severity_override_high(self):
        result = _run(
            events_by_event_name={"Decrypt": [_event(KEY_ARN_A, pcr0=UNKNOWN_PCR0)]},
            audit_config={
                "enclave_golden_pcr_values": {"PCR0": [GOLDEN_PCR0]},
                "enclave_unknown_image_severity": "high",
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].check_metadata.Severity.value == "high"

    def test_severity_override_invalid_falls_back_to_medium(self):
        result = _run(
            events_by_event_name={"Decrypt": [_event(KEY_ARN_A, pcr0=UNKNOWN_PCR0)]},
            audit_config={
                "enclave_golden_pcr_values": {"PCR0": [GOLDEN_PCR0]},
                "enclave_unknown_image_severity": "critical",
            },
        )
        assert len(result) == 1
        assert result[0].check_metadata.Severity.value == "medium"

    def test_debug_events_discarded_from_scope(self):
        # Debug events (zeroed PCR0/1/2) belong to kms_key_enclave_debug_attestation_detected; not reported here.
        result = _run(
            events_by_event_name={"Decrypt": [_event(KEY_ARN_A, debug=True)]},
            audit_config={"enclave_golden_pcr_values": {"PCR0": [GOLDEN_PCR0]}},
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "No non-debug attestation events" in result[0].status_extended

    def test_mixed_debug_and_unknown_reports_fail_only_on_unknown(self):
        result = _run(
            events_by_event_name={
                "Decrypt": [
                    _event(KEY_ARN_A, debug=True),
                    _event(KEY_ARN_A, pcr0=UNKNOWN_PCR0),
                ]
            },
            audit_config={"enclave_golden_pcr_values": {"PCR0": [GOLDEN_PCR0]}},
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_pcr_bucket_without_golden_is_ignored(self):
        # Only PCR0 has a golden list; PCR1 unknown value should NOT fail.
        result = _run(
            events_by_event_name={
                "Decrypt": [_event(KEY_ARN_A, pcr0=GOLDEN_PCR0, pcr1="ffff" * 24)]
            },
            audit_config={"enclave_golden_pcr_values": {"PCR0": [GOLDEN_PCR0]}},
        )
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_case_insensitive_pcr_value_match(self):
        # Golden values are lowercased at load; observed values also
        # lowercased. Mixed-case hex should still match.
        result = _run(
            events_by_event_name={
                "Decrypt": [_event(KEY_ARN_A, pcr0=GOLDEN_PCR0.upper())]
            },
            audit_config={"enclave_golden_pcr_values": {"PCR0": [GOLDEN_PCR0]}},
        )
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_target_key_filter_narrows_reports(self):
        events = {
            "Decrypt": [
                _event(KEY_ARN_A, pcr0=UNKNOWN_PCR0),
                _event(KEY_ARN_B, pcr0=UNKNOWN_PCR0),
            ]
        }
        result = _run(
            events_by_event_name=events,
            audit_config={
                "enclave_golden_pcr_values": {"PCR0": [GOLDEN_PCR0]},
                "enclave_unknown_image_target_key_ids": [KEY_ARN_A.rsplit("/", 1)[-1]],
            },
        )
        arns = {r.resource_arn for r in result}
        assert arns == {KEY_ARN_A}

    def test_multiple_keys_mixed_verdicts(self):
        events = {
            "Decrypt": [
                _event(KEY_ARN_A, pcr0=UNKNOWN_PCR0),
                _event(KEY_ARN_B, pcr0=GOLDEN_PCR0),
            ]
        }
        result = _run(
            events_by_event_name=events,
            audit_config={"enclave_golden_pcr_values": {"PCR0": [GOLDEN_PCR0]}},
        )
        by_arn = {r.resource_arn: r.status for r in result}
        assert by_arn[KEY_ARN_A] == "FAIL"
        assert by_arn[KEY_ARN_B] == "PASS"

    def test_truncated_page_no_unknown_reports_manual_coverage_limited(self):
        result = _run(
            events_by_event_name={"Decrypt": [_event(KEY_ARN_A)]},
            audit_config={"enclave_golden_pcr_values": {"PCR0": [GOLDEN_PCR0]}},
            truncated=True,
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            "event cap" in result[0].status_extended
            or "truncation" in result[0].status_extended
        )

    def test_truncated_page_with_unknown_still_fails(self):
        result = _run(
            events_by_event_name={"Decrypt": [_event(KEY_ARN_A, pcr0=UNKNOWN_PCR0)]},
            audit_config={"enclave_golden_pcr_values": {"PCR0": [GOLDEN_PCR0]}},
            truncated=True,
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_malformed_event_dropped(self):
        result = _run(
            events_by_event_name={"Decrypt": [{"CloudTrailEvent": "not-json"}]},
            audit_config={"enclave_golden_pcr_values": {"PCR0": [GOLDEN_PCR0]}},
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"

    def test_imagesha384_collapses_to_pcr0(self):
        # Only ImageSha384 field present should collapse to PCR0 bucket.
        recipient = {
            "attestationDocumentModuleId": f"{INSTANCE_ID}-enc9876abcd543210ef12",
            "attestationDocumentEnclaveImageDigest": UNKNOWN_PCR0,
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
            "EventTime": datetime(2026, 7, 15, tzinfo=timezone.utc),
            "CloudTrailEvent": json.dumps(payload),
        }
        result = _run(
            events_by_event_name={"Decrypt": [raw]},
            audit_config={"enclave_golden_pcr_values": {"PCR0": [GOLDEN_PCR0]}},
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "PCR0" in result[0].status_extended

    def test_multi_region_iterates_every_region(self):
        # LookupEvents is per-region even for multi-region trails.
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
        kms_client.audit_config = {"enclave_golden_pcr_values": {"PCR0": [GOLDEN_PCR0]}}
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
            from prowler.providers.aws.services.kms.kms_key_enclave_attestation_unknown_image.kms_key_enclave_attestation_unknown_image import (
                kms_key_enclave_attestation_unknown_image,
            )

            kms_key_enclave_attestation_unknown_image().execute()

        assert set(calls_per_region.keys()) == {"us-east-1", "eu-west-1", "ap-south-1"}
        assert all(
            v == len(SENSITIVE_ENCLAVE_KMS_EVENTS) for v in calls_per_region.values()
        )

    def test_lookup_error_reported_as_incomplete_coverage(self):
        result = _run(
            events_by_event_name={},
            audit_config={"enclave_golden_pcr_values": {"PCR0": [GOLDEN_PCR0]}},
            lookup_error="AccessDeniedException",
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "CloudTrail lookup failed" in result[0].status_extended
        assert "AccessDeniedException" in result[0].status_extended

    def test_recipient_missing_or_non_dict_dropped(self):
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
                    "EventTime": datetime(2026, 7, 15, tzinfo=timezone.utc),
                    "CloudTrailEvent": json.dumps(payload),
                }
            )
        result = _run(
            events_by_event_name={"Decrypt": malformed},
            audit_config={"enclave_golden_pcr_values": {"PCR0": [GOLDEN_PCR0]}},
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"

    def test_missing_module_id_dropped(self):
        payload = {
            "eventName": "Decrypt",
            "additionalEventData": {
                "recipient": {
                    "attestationDocumentEnclaveImageDigest": GOLDEN_PCR0,
                    # attestationDocumentModuleId missing
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
            "EventTime": datetime(2026, 7, 15, tzinfo=timezone.utc),
            "CloudTrailEvent": json.dumps(payload),
        }
        result = _run(
            events_by_event_name={"Decrypt": [raw]},
            audit_config={"enclave_golden_pcr_values": {"PCR0": [GOLDEN_PCR0]}},
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
