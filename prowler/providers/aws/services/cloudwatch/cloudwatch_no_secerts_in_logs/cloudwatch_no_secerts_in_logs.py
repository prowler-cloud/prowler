import os
import tempfile
from json import dumps, loads
from datetime import datetime
from datetime import timezone

from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudwatch.cloudwatch_client import (
    cloudwatch_client,
)
from prowler.providers.aws.services.cloudwatch.logs_client import logs_client


class cloudwatch_no_secerts_in_logs(Check):
    def execute(self):
        findings = []
        for log_group in logs_client.log_groups:
            report = Check_Report_AWS(self.metadata())
            report.status = "PASS"
            report.status_extended = (
                f"No secrets found in {log_group.name} log group."
            )
            report.region = cloudwatch_client.region
            report.resource_id = log_group.arn
            log_group_secrets = []
            if log_group.log_streams:
                for log_stream_name in log_group.log_streams:
                    log_stream_secrets = {}
                    log_stream_data = '\n'.join([dumps(event["message"]) for event in log_group.log_streams[log_stream_name]])
                    log_stream_secrets_output = detect_secrets_scan(log_stream_data)
                    
                    if log_stream_secrets_output:
                        for secret in log_stream_secrets_output:
                            flagged_event = log_group.log_streams[log_stream_name][secret["line_number"]-1]
                            cloudwatch_timestamp = convert_to_cloudwatch_timestamp_format(flagged_event["timestamp"])
                            if cloudwatch_timestamp not in log_stream_secrets.keys():
                                log_stream_secrets[cloudwatch_timestamp] = SecretsDict()
                            
                            try:
                                log_event_data = dumps(loads(flagged_event["message"]), indent=2)
                            except:
                                log_event_data = dumps(flagged_event["message"], indent=2)
                            if len(log_event_data.split('\n')) > 1:
                                # Can get more informative output if there is more than 1 line.
                                # Will rescan just this event to get the type of secret and the line number
                                event_detect_secrets_output = detect_secrets_scan(log_event_data)
                                [
                                    log_stream_secrets[cloudwatch_timestamp].add_secret(secret['line_number'],secret['type'])
                                    for secret in event_detect_secrets_output
                                ]
                            else:
                                log_stream_secrets[cloudwatch_timestamp].add_secret(1,secret['type'])
                    if log_stream_secrets:
                        secrets_string = '; '.join([f"At {timestamp} - {log_stream_secrets[timestamp].to_string()}" for timestamp in log_stream_secrets])
                        log_group_secrets.append(f"In log stream {log_stream_name}: {secrets_string}")
            if log_group_secrets:
                secrets_string = ". ".join(log_group_secrets)
                report.status = "FAIL"
                report.status_extended = f"Potential secrets found in log group. {secrets_string}"
            findings.append(report)
        return findings

def convert_to_cloudwatch_timestamp_format(epoch_time):
    date_time = datetime.fromtimestamp( epoch_time/1000, datetime.now(timezone.utc).astimezone().tzinfo)  
    datetime_str = date_time.strftime("%Y-%m-%dT%H:%M:%S.!%f!%z") # use exclamation marks as placeholders to convert datetime str to cloudwatch timestamp str
    datetime_parts = datetime_str.split('!')
    return datetime_parts[0] + datetime_parts[1][:-3] + datetime_parts[2][:-2] + ':' + datetime_parts[2][-2:] # Removes the microseconds, and places a ':' character in the timezone offset


def detect_secrets_scan(data):
    # Should move this to the utils file, but will leave that for a merge request after this one is accepted
    temp_data_file = tempfile.NamedTemporaryFile(delete=False)
    temp_data_file.write(bytes(data, encoding="raw_unicode_escape"))
    temp_data_file.close()

    secrets = SecretsCollection()
    with default_settings():
        secrets.scan_file(temp_data_file.name)
    os.remove(temp_data_file.name)

    detect_secrets_output = secrets.json()
    if detect_secrets_output:
        return detect_secrets_output[temp_data_file.name]
    else:
        return None

class SecretsDict(dict):
    # Using this dict to remove duplicates of the secret type showing up multiple times on the same line
    # Also includes the to_string method
    def add_secret(self,line_number,secret_type):
        if line_number not in self.keys():
            self[line_number] = [secret_type]
        else:
            if secret_type not in self[line_number]:
                self[line_number] += [secret_type]
    
    def to_string(self):
        return ", ".join([f"{','.join(secret_types)} on line {line_number}" for line_number,secret_types in sorted(self.items())])