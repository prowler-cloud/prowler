import random

from botocore.exceptions import ClientError

from prowler.lib.check.models import Check, Check_Report
from prowler.providers.aws.services.s3.s3_client import s3_client


class s3_bucket_object_public(Check):
    def execute(self):
        findings = []

        for bucket in s3_client.buckets.values():
            report = Check_Report(self.metadata(), bucket)

            report.resource_id = bucket.name
            report.resource_arn = bucket.arn
            report.region = bucket.region
            report.resource_tags = bucket.tags

            report.status = "PASS"
            report.status_extended = (
                f"No public objects found in bucket {bucket.name} (sampled)."
            )

            try:
                regional_client = s3_client.regional_clients[bucket.region]
                objects = regional_client.list_objects_v2(
                    Bucket=bucket.name, MaxKeys=100
                )

                if "Contents" in objects:
                    all_keys = [obj["Key"] for obj in objects["Contents"]]
                    sample_keys = random.sample(all_keys, min(len(all_keys), 3))

                    public_objects_found = []

                    for key in sample_keys:
                        acl = regional_client.get_object_acl(
                            Bucket=bucket.name, Key=key
                        )

                        for grant in acl.get("Grants", []):
                            grantee = grant.get("Grantee", {})
                            if grantee.get(
                                "Type"
                            ) == "Group" and "AllUsers" in grantee.get("URI", ""):
                                public_objects_found.append(key)
                                break

                    if public_objects_found:
                        report.status = "FAIL"
                        report.status_extended = f"S3 Bucket {bucket.name} contains public objects: {', '.join(public_objects_found)}."

                else:
                    report.status_extended = f"Bucket {bucket.name} is empty."

            except ClientError as error:
                if error.response["Error"]["Code"] == "AccessDenied":
                    report.status = "MANUAL"
                    report.status_extended = (
                        f"Access Denied when checking objects in bucket {bucket.name}."
                    )
                else:
                    report.status = "MANUAL"
                    report.status_extended = (
                        f"Could not check objects in bucket {bucket.name}: {error}"
                    )
            except Exception as error:
                report.status = "MANUAL"
                report.status_extended = (
                    f"An error occurred in bucket {bucket.name}: {error}"
                )

            findings.append(report)

        return findings
