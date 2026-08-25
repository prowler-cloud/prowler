from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)
from prowler.providers.aws.services.kms.kms_client import kms_client
from prowler.providers.aws.services.kms.lib.enclave import (
    DEFAULT_ENCLAVE_DEBUG_LOOKBACK_HOURS,
    DEFAULT_ENCLAVE_DEBUG_MAX_EVENTS,
    ENCLAVE_DEBUG_CONFIG_LOOKBACK_KEY,
    ENCLAVE_DEBUG_CONFIG_MAX_EVENTS_KEY,
    ENCLAVE_DEBUG_CONFIG_TARGET_KEYS_KEY,
    SENSITIVE_ENCLAVE_KMS_EVENTS,
    key_id_from_arn,
    parse_enclave_kms_event,
    resolve_kms_key_resource,
    synthetic_account_kms_resource,
)


class kms_key_enclave_debug_attestation_detected(Check):
    """Detect Nitro Enclave debug-mode attestation on KMS calls (CloudTrail).

    Enclaves launched with ``--debug-mode`` produce attestation documents
    whose image/kernel/application PCRs (``PCR0``, ``PCR1``, ``PCR2``) are
    zeroed. When such an enclave calls a sensitive KMS operation
    (``Decrypt``, ``GenerateDataKey``, ``GenerateDataKeyPair``,
    ``GenerateRandom``) the recipient attestation is logged in CloudTrail
    with those zeroed PCRs. This Tier 1, read-only check scans CloudTrail
    events and attributes findings to the KMS keys that were targeted.

    Verdicts per KMS key ARN observed in CloudTrail events (or per target
    key in ``enclave_debug_target_key_ids`` if configured):

    - FAIL: at least one CloudTrail event against the key has zeroed PCR0/1/2.
    - PASS: events observed against the key, none debug, and the lookup
      covered the full window (no page truncation).
    - MANUAL: no events attributable to the key in the window, or the
      event cap was reached without a confirmed debug event
      (coverage-limited — fail-closed).
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the CloudTrail-based debug-attestation check.

        Iterates every configured KMS trail (or the multi-region trail if
        available), issues paginated ``lookup_events`` calls for each
        sensitive enclave KMS event name, groups the parsed events by key
        ARN, and emits one report per observed (or targeted) KMS key.

        Returns:
            list[Check_Report_AWS]: one report per KMS key evaluated.
        """
        findings = []

        lookback_hours = kms_client.audit_config.get(
            ENCLAVE_DEBUG_CONFIG_LOOKBACK_KEY,
            DEFAULT_ENCLAVE_DEBUG_LOOKBACK_HOURS,
        )
        max_events = kms_client.audit_config.get(
            ENCLAVE_DEBUG_CONFIG_MAX_EVENTS_KEY,
            DEFAULT_ENCLAVE_DEBUG_MAX_EVENTS,
        )
        target_key_ids = set(
            kms_client.audit_config.get(ENCLAVE_DEBUG_CONFIG_TARGET_KEYS_KEY, []) or []
        )
        # Fall back to defaults if the operator writes a non-numeric value in
        # ``audit_config`` (e.g. a stray string). Do not abort the check.
        # Normalize ``lookback_hours`` in place so status messages report the
        # value actually used for the CloudTrail lookup, not the invalid input.
        try:
            lookback_hours = max(1, int(lookback_hours))
        except (TypeError, ValueError):
            lookback_hours = DEFAULT_ENCLAVE_DEBUG_LOOKBACK_HOURS
        lookback_minutes = lookback_hours * 60
        try:
            max_events = max(1, int(max_events))
        except (TypeError, ValueError):
            max_events = DEFAULT_ENCLAVE_DEBUG_MAX_EVENTS

        trails = (
            list(cloudtrail_client.trails.values()) if cloudtrail_client.trails else []
        )
        if not trails:
            return self._emit_no_trail_manual(target_key_ids)

        # LookupEvents is a per-region API even for multi-region trails, so
        # iterate over every audited region. A multi-region trail in us-east-1
        # cannot expose eu-west-1 KMS events via a us-east-1 lookup.
        regions_to_scan = sorted(cloudtrail_client.regional_clients.keys())

        events_by_key: dict = {}
        any_coverage_gap = False
        coverage_errors: list = []
        total_events_processed = 0

        for region in regions_to_scan:
            for event_name in SENSITIVE_ENCLAVE_KMS_EVENTS:
                if total_events_processed >= max_events:
                    any_coverage_gap = True
                    break
                page_events, truncated, error = cloudtrail_client._lookup_events_page(
                    region=region,
                    event_name=event_name,
                    minutes=lookback_minutes,
                )
                if error is not None:
                    any_coverage_gap = True
                    coverage_errors.append(f"{region}:{event_name} ({error})")
                    continue
                for raw in page_events or []:
                    parsed = parse_enclave_kms_event(raw)
                    if parsed is None:
                        continue
                    key_arn = parsed["key_arn"]
                    if key_arn is None:
                        continue
                    if (
                        target_key_ids
                        and key_id_from_arn(key_arn) not in target_key_ids
                    ):
                        continue
                    events_by_key.setdefault(key_arn, []).append(parsed)
                total_events_processed += len(page_events or [])
                if truncated:
                    any_coverage_gap = True
            if total_events_processed >= max_events:
                break

        keys_to_report = set(events_by_key.keys())
        if target_key_ids:
            for key in kms_client.keys:
                if key_id_from_arn(key.arn) in target_key_ids:
                    keys_to_report.add(key.arn)

        if not keys_to_report:
            report = Check_Report_AWS(
                metadata=self.metadata(),
                resource=synthetic_account_kms_resource(
                    kms_client.audited_account, kms_client.region
                ),
            )
            report.status = "MANUAL"
            base = (
                f"No KMS-from-enclave attestation events found in the last "
                f"{lookback_hours}h. Debug-mode status cannot be determined "
                f"from available data; enclaves that never call KMS in the "
                f"window are not observable via this check."
            )
            if coverage_errors:
                report.status_extended = (
                    f"{base} Additionally, CloudTrail lookup failed for "
                    f"{len(coverage_errors)} region/event pair(s): "
                    f"{', '.join(coverage_errors[:5])}"
                    f"{'...' if len(coverage_errors) > 5 else ''}. "
                    f"Coverage is incomplete."
                )
            else:
                report.status_extended = base
            findings.append(report)
            return findings

        for key_arn in sorted(keys_to_report):
            report = Check_Report_AWS(
                metadata=self.metadata(),
                resource=resolve_kms_key_resource(kms_client, key_arn),
            )
            events = events_by_key.get(key_arn, [])
            debug_events = [e for e in events if e["is_debug"]]

            if debug_events:
                sample = sorted(debug_events, key=lambda e: str(e["event_time"]))[0]
                report.status = "FAIL"
                report.status_extended = (
                    f"KMS key {key_arn} received a "
                    f"{sample['event_name']} call at {sample['event_time']} "
                    f"with an attestation document whose PCR0/1/2 are zeroed, "
                    f"indicating a Nitro Enclave running in --debug-mode."
                )
            elif not events:
                report.status = "MANUAL"
                report.status_extended = (
                    f"KMS key {key_arn} has no KMS-from-enclave attestation "
                    f"events in the last {lookback_hours}h; debug-mode "
                    f"status cannot be verified for this key."
                )
            elif any_coverage_gap:
                report.status = "MANUAL"
                report.status_extended = (
                    f"KMS key {key_arn} observed {len(events)} enclave "
                    f"attestation events with legitimate PCRs, but the "
                    f"CloudTrail lookup reached the event cap "
                    f"({max_events}) or page truncation. A debug event may "
                    f"exist beyond the cap; narrow "
                    f"'enclave_debug_lookback_window_hours' or raise "
                    f"'enclave_debug_max_events' for confirmatory coverage."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"KMS key {key_arn} observed {len(events)} enclave "
                    f"attestation events in the last {lookback_hours}h and "
                    f"none carry zeroed PCR0/1/2."
                )
            findings.append(report)
        return findings

    def _emit_no_trail_manual(self, target_key_ids: set[str]) -> list[Check_Report_AWS]:
        """Emit MANUAL findings when no CloudTrail trail is configured.

        Without a trail the check has no data source, so it fails closed
        with MANUAL against every candidate key (or a synthetic
        account-scoped resource when the account has no KMS keys either).

        Args:
            target_key_ids: Optional filter of KMS key-ids to report on.
                When empty every customer-managed key is a candidate.

        Returns:
            list[Check_Report_AWS]: One MANUAL report per candidate key,
            or a single account-scoped MANUAL when no keys exist.
        """
        findings = []
        candidate_keys = [
            k
            for k in kms_client.keys
            if not target_key_ids or key_id_from_arn(k.arn) in target_key_ids
        ]
        if not candidate_keys:
            report = Check_Report_AWS(
                metadata=self.metadata(),
                resource=synthetic_account_kms_resource(
                    kms_client.audited_account, kms_client.region
                ),
            )
            report.status = "MANUAL"
            report.status_extended = (
                "No CloudTrail trails are configured in the account; "
                "debug-attestation activity cannot be observed."
            )
            findings.append(report)
            return findings
        for key in candidate_keys:
            report = Check_Report_AWS(metadata=self.metadata(), resource=key)
            report.status = "MANUAL"
            report.status_extended = (
                f"KMS key {key.arn} debug-attestation status cannot be "
                f"verified: no CloudTrail trails are configured in the "
                f"account. Enable CloudTrail to observe KMS-from-enclave "
                f"activity."
            )
            findings.append(report)
        return findings
