from json import dumps, loads

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import detect_secrets_scan
from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
    convert_to_cloudwatch_timestamp_format,
)
from prowler.providers.aws.services.cloudwatch.logs_client import logs_client


class cloudwatch_log_group_no_secrets_in_logs(Check):
    def execute(self):
        findings = []
        for log_group in logs_client.log_groups:
            report = Check_Report_AWS(self.metadata())
            report.status = "PASS"
            report.status_extended = f"No secrets found in {log_group.name} log group."
            report.region = log_group.region
            report.resource_id = log_group.name
            report.resource_arn = log_group.arn
            log_group_secrets = []
            if log_group.log_streams:
                for log_stream_name in log_group.log_streams:
                    log_stream_secrets = {}
                    log_stream_data = "\n".join(
                        [
                            dumps(event["message"])
                            for event in log_group.log_streams[log_stream_name]
                        ]
                    )
                    log_stream_secrets_output = detect_secrets_scan(log_stream_data)

                    if log_stream_secrets_output:
                        for secret in log_stream_secrets_output:
                            flagged_event = log_group.log_streams[log_stream_name][
                                secret["line_number"] - 1
                            ]
                            cloudwatch_timestamp = (
                                convert_to_cloudwatch_timestamp_format(
                                    flagged_event["timestamp"]
                                )
                            )
                            if cloudwatch_timestamp not in log_stream_secrets.keys():
                                log_stream_secrets[cloudwatch_timestamp] = SecretsDict()

                            try:
                                log_event_data = dumps(
                                    loads(flagged_event["message"]), indent=2
                                )
                            except Exception:
                                log_event_data = dumps(
                                    flagged_event["message"], indent=2
                                )
                            if len(log_event_data.split("\n")) > 1:
                                # Can get more informative output if there is more than 1 line.
                                # Will rescan just this event to get the type of secret and the line number
                                event_detect_secrets_output = detect_secrets_scan(
                                    log_event_data
                                )
                                if event_detect_secrets_output:
                                    for secret in event_detect_secrets_output:
                                        log_stream_secrets[
                                            cloudwatch_timestamp
                                        ].add_secret(
                                            secret["line_number"], secret["type"]
                                        )
                            else:
                                log_stream_secrets[cloudwatch_timestamp].add_secret(
                                    1, secret["type"]
                                )
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
            if log_group_secrets:
                secrets_string = "; ".join(log_group_secrets)
                report.status = "FAIL"
                report.status_extended = f"Potential secrets found in log group {log_group.name} {secrets_string}."
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
