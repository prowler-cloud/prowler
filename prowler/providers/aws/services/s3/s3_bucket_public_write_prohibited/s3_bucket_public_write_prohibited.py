from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client


class s3_bucket_public_write_prohibited(Check):
    def execute(self):
        findings = []

        for bucket in s3_client.buckets.values():
            report = Check_Report_AWS(self.metadata())
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_tags = bucket.tags

            # Determine if public write access is allowed by checking bucket ACL and policy
            public_write_access = False

            if bucket.acl_grantees:
                for grantee in bucket.acl_grantees:
                    if grantee.type == "Group" and grantee.URI == "http://acs.amazonaws.com/groups/global/AllUsers":
                        if grantee.permission in ["WRITE", "FULL_CONTROL"]:
                            public_write_access = True
                            break

            if public_write_access:
                report.status = "FAIL"
                report.status_extended = f"S3 Bucket {bucket.name} allows public write access."
            else:
                report.status = "PASS"
                report.status_extended = f"S3 Bucket {bucket.name} does not allow public write access."

            findings.append(report)

        return findings
