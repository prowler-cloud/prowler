from json import dumps, loads

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
    convert_to_cloudwatch_timestamp_format,
)
from prowler.providers.aws.services.cloudwatch.logs_client import logs_client


class cloudwatch_log_group_no_secrets_in_logs(Check):
    def execute(self):
        findings = []
        if not logs_client.log_groups:
            return findings

        secrets_ignore_patterns = logs_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = logs_client.audit_config.get("secrets_validate", False)

        # Phase 1: batch-scan every (log group, log stream). Payloads are yielded
        # lazily so only a chunk is written/held at a time, which matters for
        # accounts with very large numbers of log groups/streams. The log group
        # ARN (not its name) keys every map below, since group and stream names
        # are not unique across regions and would otherwise collide.
        def stream_payloads():
            for log_group in logs_client.log_groups.values():
                if not log_group.log_streams:
                    continue
                for log_stream_name, events in log_group.log_streams.items():
                    yield (
                        (log_group.arn, log_stream_name),
                        "\n".join(dumps(event["message"]) for event in events),
                    )

        # A scanner failure here must never look like "no secrets": log groups
        # whose streams could not be scanned are reported MANUAL in Phase 4.
        stream_scan_error = None
        try:
            stream_results = detect_secrets_scan_batch(
                stream_payloads(),
                excluded_secrets=secrets_ignore_patterns,
                validate=validate,
            )
        except SecretsScanError as error:
            stream_results = {}
            stream_scan_error = error

        # Phase 2: plan the per-event secrets for each flagged stream and collect
        # the multiline events to rescan. Each multiline event is rescanned once
        # to resolve per-line detail; the rescans are batched in Phase 3 instead
        # of one subprocess per event. The event index (``line_number - 1``,
        # since Phase 1 joins one event per line) is the per-event discriminator:
        # a CloudWatch stream can hold several events sharing one millisecond
        # timestamp, so keying only by timestamp would let a later multiline
        # event overwrite an earlier one's payload and lose secret evidence.
        # Output still groups/displays by timestamp; only the rescan identity is
        # per event.
        # stream_plans: (group arn, stream) ->
        #     {timestamp: {event index: {"multiline", "types"}}}
        # rescan_payloads: (group arn, stream, timestamp, event index) ->
        #     multiline event data
        stream_plans = {}
        rescan_payloads = {}
        groups_with_rescan = set()  # group arns that depend on the Phase 3 rescan
        for log_group in logs_client.log_groups.values():
            for log_stream_name in log_group.log_streams or {}:
                stream_secrets = stream_results.get((log_group.arn, log_stream_name))
                if not stream_secrets:
                    continue
                events = log_group.log_streams[log_stream_name]
                plan = {}
                for secret in stream_secrets:
                    event_index = secret["line_number"] - 1
                    flagged_event = events[event_index]
                    cloudwatch_timestamp = convert_to_cloudwatch_timestamp_format(
                        flagged_event["timestamp"]
                    )
                    try:
                        log_event_data = dumps(
                            loads(flagged_event["message"]), indent=2
                        )
                    except Exception:
                        log_event_data = dumps(flagged_event["message"], indent=2)
                    multiline = len(log_event_data.split("\n")) > 1
                    events_at_timestamp = plan.setdefault(cloudwatch_timestamp, {})
                    if event_index not in events_at_timestamp:
                        events_at_timestamp[event_index] = {
                            "multiline": multiline,
                            "types": [],
                        }
                    if multiline:
                        # More informative output is possible with more than one
                        # line: the event is rescanned to get the type and line
                        # number of each secret.
                        rescan_payloads[
                            (
                                log_group.arn,
                                log_stream_name,
                                cloudwatch_timestamp,
                                event_index,
                            )
                        ] = log_event_data
                        groups_with_rescan.add(log_group.arn)
                    else:
                        events_at_timestamp[event_index]["types"].append(secret["type"])
                stream_plans[(log_group.arn, log_stream_name)] = plan

        # Phase 3: one batched rescan for all multiline flagged events. Validation
        # is never enabled here: this rescan only resolves line numbers for
        # display and must not re-authenticate the secret.
        # If the rescan fails we know secrets were already found in Phase 1, so
        # the affected groups must not silently pass; they are reported MANUAL.
        rescan_scan_error = None
        rescan_results = {}
        if rescan_payloads:
            try:
                rescan_results = detect_secrets_scan_batch(
                    rescan_payloads, excluded_secrets=secrets_ignore_patterns
                )
            except SecretsScanError as error:
                rescan_scan_error = error

        # Phase 4: assemble one report per log group.
        for log_group in logs_client.log_groups.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=log_group)
            report.status = "PASS"
            report.status_extended = f"No secrets found in {log_group.name} log group."

            # The stream scan failed: we cannot conclude this group is clean.
            if stream_scan_error and log_group.log_streams:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not scan log group {log_group.name} for secrets: "
                    f"{stream_scan_error}; manual review is required."
                )
                findings.append(report)
                continue

            log_group_secrets = []
            all_secrets = []
            for log_stream_name in log_group.log_streams or {}:
                stream_secrets = stream_results.get((log_group.arn, log_stream_name))
                if not stream_secrets:
                    continue
                all_secrets.extend(stream_secrets)
                log_stream_secrets = {}
                for cloudwatch_timestamp, events_at_timestamp in stream_plans[
                    (log_group.arn, log_stream_name)
                ].items():
                    secrets_dict = SecretsDict()
                    # Multiple events can share one timestamp; aggregate each
                    # event's secrets into the timestamp's display entry.
                    for event_index, entry in events_at_timestamp.items():
                        if entry["multiline"]:
                            for event_secret in rescan_results.get(
                                (
                                    log_group.arn,
                                    log_stream_name,
                                    cloudwatch_timestamp,
                                    event_index,
                                ),
                                [],
                            ):
                                secrets_dict.add_secret(
                                    event_secret["line_number"], event_secret["type"]
                                )
                        else:
                            for secret_type in entry["types"]:
                                secrets_dict.add_secret(1, secret_type)
                    # Only record the event when at least one non-ignored secret
                    # remains after the rescan. A multiline event whose secrets
                    # were all dropped by ``secrets_ignore_patterns`` leaves an
                    # empty SecretsDict, which must not produce a FAIL with no
                    # actual secret evidence.
                    if secrets_dict:
                        log_stream_secrets[cloudwatch_timestamp] = secrets_dict
                if log_stream_secrets:
                    secrets_string = "; ".join(
                        [
                            f"at {timestamp} - {log_stream_secrets[timestamp].to_string()}"
                            for timestamp in log_stream_secrets
                        ]
                    )
                    log_group_secrets.append(
                        f"in log stream {log_stream_name} {secrets_string}"
                    )
            # The multiline rescan failed for a group that had flagged secrets:
            # detail is unavailable, so report MANUAL rather than risk a false
            # PASS when every flagged event was multiline.
            if rescan_scan_error and log_group.arn in groups_with_rescan:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Secrets were detected in log group {log_group.name} but the "
                    f"detailed rescan failed: {rescan_scan_error}; manual review "
                    "is required."
                )
            elif log_group_secrets:
                secrets_string = "; ".join(log_group_secrets)
                report.status = "FAIL"
                report.status_extended = f"Potential secrets found in log group {log_group.name} {secrets_string}."
                annotate_verified_secrets(report, all_secrets)
            findings.append(report)
        return findings


class SecretsDict(dict):
    # Using this dict to remove duplicates of the secret type showing up multiple times on the same line
    # Also includes the to_string method
    def add_secret(self, line_number, secret_type):
        if line_number not in self.keys():
            self[line_number] = [secret_type]
        else:
            if secret_type not in self[line_number]:
                self[line_number] += [secret_type]

    def to_string(self):
        return ", ".join(
            [
                f"{', '.join(secret_types)} on line {line_number}"
                for line_number, secret_types in sorted(self.items())
            ]
        )
