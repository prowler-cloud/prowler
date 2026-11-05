from prowler.lib.check.models import Check, Check_Report_AWS, Severity
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)
from prowler.providers.aws.services.kms.kms_client import kms_client
from prowler.providers.aws.services.kms.lib.enclave import (
    DEFAULT_ENCLAVE_UNKNOWN_IMAGE_LOOKBACK_HOURS,
    DEFAULT_ENCLAVE_UNKNOWN_IMAGE_MAX_EVENTS,
    DEFAULT_ENCLAVE_UNKNOWN_IMAGE_SEVERITY,
    ENCLAVE_UNKNOWN_IMAGE_ALLOWED_SEVERITIES,
    ENCLAVE_UNKNOWN_IMAGE_CONFIG_LOOKBACK_KEY,
    ENCLAVE_UNKNOWN_IMAGE_CONFIG_MAX_EVENTS_KEY,
    ENCLAVE_UNKNOWN_IMAGE_CONFIG_SEVERITY_KEY,
    ENCLAVE_UNKNOWN_IMAGE_CONFIG_TARGET_KEYS_KEY,
    GOLDEN_PCR_CONFIG_KEY,
    SENSITIVE_ENCLAVE_KMS_EVENTS,
    key_id_from_arn,
    normalize_golden_pcr_config,
    parse_enclave_kms_event,
    resolve_kms_key_resource,
    synthetic_account_kms_resource,
    unknown_pcrs,
)


class kms_key_enclave_attestation_unknown_image(Check):
    """Detect KMS attestation events from unrecognized enclave images.

    Complementary to ``kms_key_enclave_attestation_pcr_mismatch``:

    - ``kms_key_enclave_attestation_pcr_mismatch`` audits the KMS **key
      policy** (config-time). It detects when a policy authorises PCR
      values not present in the operator's golden list.
    - This check audits **runtime CloudTrail activity**. It detects when
      any enclave actually calls KMS with PCR values not present in the
      golden list — even if the key policy would happen to allow them.
      Useful when the golden list has been updated but a policy is still
      permissive, or when the policy is broad enough to accept images the
      operator never audited.

    Verdicts per KMS key ARN observed in CloudTrail events (or per target
    key in ``enclave_unknown_image_target_key_ids`` if configured):

    - FAIL: at least one non-debug attestation event references a PCR
      value that is NOT in the configured golden list.
    - PASS: events observed against the key, every referenced PCR present
      in the golden list, and the lookup covered the full window.
    - MANUAL: no golden PCR values configured; no non-debug attestation
      events found in the window; or the event cap was reached without a
      confirmed unknown event (coverage-limited fail-closed).

    Debug-mode events (all-zero PCRs) are silently discarded — they are
    scoped to ``kms_key_enclave_debug_attestation_detected`` (Check 10-A)
    to avoid double reporting.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the unknown-image attestation check.

        Iterates every configured KMS trail (deduping on multi-region),
        walks CloudTrail attestation events, groups by KMS key ARN, and
        emits one report per observed (or targeted) key. Non-debug events
        with PCRs that fall outside the configured golden list are flagged
        FAIL; the finding severity may be overridden to ``"high"`` via
        ``enclave_unknown_image_severity`` in ``audit_config`` (applied
        through ``check_metadata.Severity`` so it propagates to output).

        Returns:
            list[Check_Report_AWS]: one report per KMS key evaluated.
        """
        findings = []
        cfg = kms_client.audit_config or {}

        golden = normalize_golden_pcr_config(cfg.get(GOLDEN_PCR_CONFIG_KEY))
        lookback_hours = cfg.get(
            ENCLAVE_UNKNOWN_IMAGE_CONFIG_LOOKBACK_KEY,
            DEFAULT_ENCLAVE_UNKNOWN_IMAGE_LOOKBACK_HOURS,
        )
        max_events = cfg.get(
            ENCLAVE_UNKNOWN_IMAGE_CONFIG_MAX_EVENTS_KEY,
            DEFAULT_ENCLAVE_UNKNOWN_IMAGE_MAX_EVENTS,
        )
        target_key_ids = set(
            cfg.get(ENCLAVE_UNKNOWN_IMAGE_CONFIG_TARGET_KEYS_KEY, []) or []
        )
        severity_override = str(
            cfg.get(
                ENCLAVE_UNKNOWN_IMAGE_CONFIG_SEVERITY_KEY,
                DEFAULT_ENCLAVE_UNKNOWN_IMAGE_SEVERITY,
            )
        ).lower()
        if severity_override not in ENCLAVE_UNKNOWN_IMAGE_ALLOWED_SEVERITIES:
            severity_override = DEFAULT_ENCLAVE_UNKNOWN_IMAGE_SEVERITY

        lookback_minutes = max(1, int(lookback_hours) * 60)
        max_events = max(1, int(max_events))

        if not golden:
            report = Check_Report_AWS(
                metadata=self.metadata(),
                resource=synthetic_account_kms_resource(
                    kms_client.audited_account, kms_client.region
                ),
            )
            report.status = "MANUAL"
            report.status_extended = (
                "Cannot verify unknown-image attestation activity: no "
                f"'{GOLDEN_PCR_CONFIG_KEY}' configured. Set a golden PCR "
                "list in audit_config and re-run this check."
            )
            findings.append(report)
            return findings

        trails = (
            list(cloudtrail_client.trails.values()) if cloudtrail_client.trails else []
        )
        if not trails:
            report = Check_Report_AWS(
                metadata=self.metadata(),
                resource=synthetic_account_kms_resource(
                    kms_client.audited_account, kms_client.region
                ),
            )
            report.status = "MANUAL"
            report.status_extended = (
                "No CloudTrail trails are configured in the account; "
                "unknown-image attestation activity cannot be observed."
            )
            findings.append(report)
            return findings

        # LookupEvents is a per-region API even for multi-region trails, so
        # iterate over every audited region.
        regions_to_scan = sorted(cloudtrail_client.regional_clients.keys())

        events_by_key: dict = {}
        any_coverage_gap = False
        coverage_errors: list = []
        total_processed = 0

        for region in regions_to_scan:
            if total_processed >= max_events:
                any_coverage_gap = True
                break
            for event_name in SENSITIVE_ENCLAVE_KMS_EVENTS:
                if total_processed >= max_events:
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
                page_events = page_events or []
                # Honour ``max_events`` at page granularity: with a cap of N
                # and a 50-event page, process only the first ``N-total`` and
                # flag coverage-incomplete for the rest.
                remaining = max_events - total_processed
                for raw in page_events[:remaining]:
                    parsed = parse_enclave_kms_event(raw)
                    if parsed is None:
                        continue
                    if parsed["is_debug"]:
                        # Debug events belong to
                        # ``kms_key_enclave_debug_attestation_detected``.
                        continue
                    key_arn = parsed["key_arn"]
                    if key_arn is None:
                        continue
                    if (
                        target_key_ids
                        and key_id_from_arn(key_arn) not in target_key_ids
                    ):
                        continue
                    unknown = unknown_pcrs(parsed["observed_pcrs"], golden)
                    events_by_key.setdefault(key_arn, []).append(
                        {**parsed, "unknown": unknown}
                    )
                total_processed += min(len(page_events), remaining)
                if len(page_events) > remaining:
                    any_coverage_gap = True
                if truncated:
                    any_coverage_gap = True

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
                f"No non-debug attestation events found in the last "
                f"{lookback_hours}h; unknown-image status cannot be "
                f"determined."
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
            # Override severity per-finding via check_metadata (Prowler-standard
            # pattern used by rds_instance_certificate_expiration and others).
            # Setting report.severity as a raw attr has no effect on output.
            report.check_metadata.Severity = Severity[severity_override]
            events = events_by_key.get(key_arn, [])
            unknown_events = [e for e in events if e["unknown"]]

            if unknown_events:
                sample = sorted(unknown_events, key=lambda e: str(e["event_time"]))[0]
                mismatches = "; ".join(
                    f"{pcr}={val}" for pcr, val in sorted(sample["unknown"].items())
                )
                report.status = "FAIL"
                report.status_extended = (
                    f"KMS key {key_arn} received a "
                    f"{sample['event_name']} call at {sample['event_time']} "
                    f"whose attestation PCR values are NOT in the "
                    f"configured golden list ({mismatches}). The enclave "
                    f"image identity cannot be verified against any known "
                    f"registry."
                )
            elif not events:
                report.status = "MANUAL"
                report.status_extended = (
                    f"KMS key {key_arn} has no non-debug attestation "
                    f"events in the last {lookback_hours}h; "
                    f"unknown-image status cannot be verified."
                )
            elif any_coverage_gap:
                report.status = "MANUAL"
                report.status_extended = (
                    f"KMS key {key_arn} observed {len(events)} attestation "
                    f"events with known PCRs, but the CloudTrail lookup "
                    f"reached the event cap ({max_events}) or page "
                    f"truncation. An unknown-image event may exist beyond "
                    f"the cap."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"KMS key {key_arn} observed {len(events)} attestation "
                    f"events in the last {lookback_hours}h; every "
                    f"referenced PCR is present in the configured golden "
                    f"list."
                )
            findings.append(report)
        return findings
