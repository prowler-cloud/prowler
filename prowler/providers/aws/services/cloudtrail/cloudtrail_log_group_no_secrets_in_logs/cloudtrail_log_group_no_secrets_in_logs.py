import json
import boto3
import gzip
from io import BytesIO
from prowler.lib.logger import logger
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)


class cloudtrail_log_group_no_secrets_in_logs(Check):
    def execute(self):
        findings = []
        secret_patterns = ["password", "secret", "key", "token"]
        s3_client = boto3.client("s3")

        if cloudtrail_client.trails is not None:
            for trail in cloudtrail_client.trails.values():
                if trail.is_logging:
                    bucket_name = trail.s3_bucket
                    prefix = f"AWSLogs/{trail.arn.split(':')[4]}/CloudTrail/"
                    result = s3_client.list_objects_v2(
                        Bucket=bucket_name, Prefix=prefix
                    )

                    if "Contents" in result:
                        for obj in result["Contents"]:
                            response = s3_client.get_object(
                                Bucket=bucket_name, Key=obj["Key"]
                            )
                            content = response["Body"].read()

                            # Check if the content is Gzip-compressed
                            if obj["Key"].endswith(".gz"):
                                with gzip.GzipFile(fileobj=BytesIO(content)) as gz:
                                    content = gz.read()

                            try:
                                content = content.decode("utf-8")
                            except UnicodeDecodeError as e:
                                logger.error(
                                    f"Failed to decode content for {obj['Key']}: {e}"
                                )
                                continue

                            if content:
                                try:
                                    events = json.loads(content).get("Records", [])
                                except json.JSONDecodeError as e:
                                    logger.error(
                                        f"Failed to decode JSON for {obj['Key']}: {e}"
                                    )
                                    continue

                                for event in events:
                                    if any(
                                        pattern in json.dumps(event)
                                        for pattern in secret_patterns
                                    ):
                                        report = Check_Report_AWS(self.metadata())
                                        report.region = trail.home_region
                                        report.resource_id = trail.name
                                        report.resource_arn = trail.arn
                                        report.resource_tags = (
                                            trail.tags if trail.tags else []
                                        )
                                        report.status = "FAIL"
                                        report.status_extended = f"Trail {trail.name} contains events with secret patterns in log file {obj['Key']}."
                                        findings.append(report)
                                        break
                                else:
                                    continue
                                break
                        else:
                            report = Check_Report_AWS(self.metadata())
                            report.region = trail.home_region
                            report.resource_id = trail.name
                            report.resource_arn = trail.arn
                            report.resource_tags = trail.tags if trail.tags else []
                            report.status = "PASS"
                            report.status_extended = f"Trail {trail.name} does not contain events with secret patterns."
                            findings.append(report)

        return findings
