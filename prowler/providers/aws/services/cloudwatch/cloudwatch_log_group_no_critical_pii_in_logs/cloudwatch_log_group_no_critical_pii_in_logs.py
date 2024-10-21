from json import dumps

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

                        # Process log data in chunks
                        chunk_size = 50000  # Adjust chunk size based on performance
                        for i in range(0, len(log_stream_events), chunk_size):
                            chunk = "\n".join(log_stream_events[i : i + chunk_size])

                            # PII detection for each chunk
                            pii_detection_result = analyzer.analyze(
                                text=chunk,
                                entities=critical_pii_entities,
                                score_threshold=1,
                                language=pii_language,
                            )
                            print(chunk)
                            print(pii_detection_result)

                            # Track cumulative character count to map PII to log event
                            cumulative_char_count = 0
                            for j, log_event in enumerate(
                                log_stream_events[i : i + chunk_size]
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
                                        if cloudwatch_timestamp not in log_stream_pii:
                                            log_stream_pii[cloudwatch_timestamp] = (
                                                SecretsDict()
                                            )

                                        # Add the detected PII entity to log_stream_pii
                                        log_stream_pii[cloudwatch_timestamp].add_secret(
                                            pii.start - cumulative_char_count,
                                            pii.entity_type,
                                        )
                                cumulative_char_count += (
                                    log_event_length + 1
                                )  # +1 to account for '\n'

                        if log_stream_pii:
                            pii_string = "; ".join(
                                [
                                    f"at {timestamp} - {log_stream_pii[timestamp].to_string()}"
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


class SecretsDict(dict):
    # Using this dict to remove duplicates of the PII type showing up multiple times on the same line
    # Also includes the to_string method
    def add_secret(self, line_number, pii_type):
        if line_number not in self.keys():
            self[line_number] = [pii_type]
        else:
            if pii_type not in self[line_number]:
                self[line_number] += [pii_type]

    def to_string(self):
        return ", ".join(
            [
                f"{', '.join(pii_types)} on line {line_number}"
                for line_number, pii_types in sorted(self.items())
            ]
        )
