from json import dumps
from typing import Set

from presidio_analyzer import AnalyzerEngine

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
    convert_to_cloudwatch_timestamp_format,
)
from prowler.providers.aws.services.cloudwatch.logs_client import logs_client


class cloudwatch_log_group_no_critical_pii_in_logs(Check):
    def execute(self):
        findings = []

        # Initialize the PII Analyzer engine
        analyzer = AnalyzerEngine()

        if logs_client.log_groups:
            critical_pii_entities = logs_client.audit_config.get(
                "critical_pii_entities",
                [
                    "CREDIT_CARD",
                    "EMAIL_ADDRESS",
                    "PHONE_NUMBER",
                    "US_SSN",
                    "US_BANK_NUMBER",
                    "IBAN_CODE",
                    "US_PASSPORT",
                ],
            )
            pii_language = logs_client.audit_config.get("pii_language", "en")
            for log_group in logs_client.log_groups.values():
                report = Check_Report_AWS(self.metadata())
                report.status = "PASS"
                report.status_extended = (
                    f"No critical PII found in {log_group.name} log group."
                )
                report.region = log_group.region
                report.resource_id = log_group.name
                report.resource_arn = log_group.arn
                report.resource_tags = log_group.tags
                log_group_pii = []

                if log_group.log_streams:
                    for log_stream_name in log_group.log_streams:
                        log_stream_pii = {}
                        log_stream_events = [
                            dumps(event["message"])
                            for event in log_group.log_streams[log_stream_name]
                        ]

                        # Process log data in manageable chunks since the limit of Presidio Analyzer is 100,000 characters
                        MAX_CHUNK_SIZE = 100000
                        for i in range(0, len(log_stream_events)):
                            chunk = log_stream_events[i]

                            # Split if chunk exceeds max allowed size for analyzer
                            if len(chunk) > MAX_CHUNK_SIZE:
                                split_chunks = [
                                    chunk[j : j + MAX_CHUNK_SIZE]
                                    for j in range(0, len(chunk), MAX_CHUNK_SIZE)
                                ]
                            else:
                                split_chunks = [chunk]

                            for split_chunk in split_chunks:
                                # PII detection for each split chunk
                                pii_detection_result = analyzer.analyze(
                                    text=split_chunk,
                                    entities=critical_pii_entities,
                                    score_threshold=1,
                                    language=pii_language,
                                )

                                # Track cumulative character count to map PII to log event
                                cumulative_char_count = 0
                                for j, log_event in enumerate(
                                    log_stream_events[i : i + len(split_chunks)]
                                ):
                                    log_event_length = len(log_event)
                                    for pii in pii_detection_result:
                                        # Check if PII start position falls within this log event
                                        if (
                                            cumulative_char_count
                                            <= pii.start
                                            < cumulative_char_count + log_event_length
                                        ):
                                            flagged_event = log_group.log_streams[
                                                log_stream_name
                                            ][j]
                                            cloudwatch_timestamp = (
                                                convert_to_cloudwatch_timestamp_format(
                                                    flagged_event["timestamp"]
                                                )
                                            )
                                            if (
                                                cloudwatch_timestamp
                                                not in log_stream_pii
                                            ):
                                                log_stream_pii[cloudwatch_timestamp] = (
                                                    SecretsDict()
                                                )

                                            # Add the detected PII entity to log_stream_pii
                                            log_stream_pii[
                                                cloudwatch_timestamp
                                            ].add_secret(
                                                pii.start - cumulative_char_count,
                                                pii.entity_type,
                                            )
                                    cumulative_char_count += (
                                        log_event_length + 1
                                    )  # +1 to account for '\n'

                        if log_stream_pii:
                            pii_string = "; ".join(
                                [
                                    f"at {timestamp} - {str(log_stream_pii[timestamp])}"
                                    for timestamp in log_stream_pii
                                ]
                            )
                            log_group_pii.append(
                                f"in log stream {log_stream_name} {pii_string}"
                            )
                if log_group_pii:
                    pii_string = "; ".join(log_group_pii)
                    report.status = "FAIL"
                    report.status_extended = f"Potential critical PII found in log group {log_group.name} {pii_string}."
                findings.append(report)
        return findings


class SecretsDict(dict[int, Set[str]]):
    """Dictionary to track unique PII types on each line."""

    def add_secret(self, line_number: int, pii_type: str) -> None:
        """Add a PII type to a specific line number, ensuring no duplicates."""
        self.setdefault(line_number, set()).add(pii_type)

    def __str__(self) -> str:
        """Generate a formatted string representation of the dictionary."""
        return ", ".join(
            f"{', '.join(sorted(pii_types))} on line {line_number}"
            for line_number, pii_types in sorted(self.items())
        )
