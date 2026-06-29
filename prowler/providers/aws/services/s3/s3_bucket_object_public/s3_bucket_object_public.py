import random

from botocore.exceptions import ClientError

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client

ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"


class s3_bucket_object_public(Check):
    def execute(self):
        findings = []

        if not s3_client.audit_config.get("s3_bucket_object_public_enabled", False):
            return findings

        max_objects = s3_client.audit_config.get(
            "s3_bucket_object_public_max_objects", 100
        )
        sample_size = s3_client.audit_config.get(
            "s3_bucket_object_public_sample_size", 3
        )

        for bucket in s3_client.buckets.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=bucket)

            try:
                regional_client = s3_client.regional_clients[bucket.region]
                objects = regional_client.list_objects_v2(
                    Bucket=bucket.name, MaxKeys=max_objects
                )

                contents = objects.get("Contents", [])
                if not contents:
                    report.status = "PASS"
                    report.status_extended = f"S3 Bucket {bucket.name} is empty."
                    findings.append(report)
                    continue

                all_keys = [obj["Key"] for obj in contents]
                sample_keys = random.sample(all_keys, min(len(all_keys), sample_size))
                sampled = len(sample_keys)

                public_objects_found = []
                for key in sample_keys:
                    acl = regional_client.get_object_acl(Bucket=bucket.name, Key=key)
                    for grant in acl.get("Grants", []):
                        grantee = grant.get("Grantee", {})
                        if (
                            grantee.get("Type") == "Group"
                            and grantee.get("URI") == ALL_USERS_URI
                        ):
                            public_objects_found.append(key)
                            break

                if public_objects_found:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"S3 Bucket {bucket.name} has public objects detected in "
                        f"spot-check sample of {sampled} objects: "
                        f"{', '.join(public_objects_found)}."
                    )
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"No public objects detected in spot-check sample of "
                        f"{sampled} objects in bucket {bucket.name}. For complete "
                        f"assurance, ensure ACLs are disabled via Object Ownership "
                        f"settings."
                    )

            except ClientError as error:
                report.status = "MANUAL"
                if error.response["Error"]["Code"] == "AccessDenied":
                    report.status_extended = (
                        f"Access Denied when spot-checking objects in bucket "
                        f"{bucket.name}."
                    )
                else:
                    report.status_extended = (
                        f"Could not spot-check objects in bucket {bucket.name}: "
                        f"{error}."
                    )

            findings.append(report)

        return findings
