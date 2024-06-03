from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)
from prowler.providers.aws.services.s3.s3_client import s3_client


class cloudtrail_logs_s3_bucket_is_not_publicly_accessible(Check):
    def execute(self):
        findings = []
        if cloudtrail_client.trails is not None:
            for trail in cloudtrail_client.trails.values():
                if trail.name:
                    trail_bucket_is_in_account = False
                    trail_bucket = trail.s3_bucket
                    report = Check_Report_AWS(self.metadata())
                    report.region = trail.home_region
                    report.resource_id = trail.name
                    report.resource_arn = trail.arn
                    report.resource_tags = trail.tags
                    report.status = "PASS"
                    if trail.is_multiregion:
                        report.status_extended = f"S3 Bucket {trail_bucket} from multiregion trail {trail.name} is not publicly accessible."
                    else:
                        report.status_extended = f"S3 Bucket {trail_bucket} from single region trail {trail.name} is not publicly accessible."
                    for bucket in s3_client.buckets:
                        # Here we need to ensure that acl_grantee is filled since if we don't have permissions to query the api for a concrete region
                        # (for example due to a SCP) we are going to try access an attribute from a None type
                        if trail_bucket == bucket.name:
                            trail_bucket_is_in_account = True
                            if bucket.acl_grantees:
                                for grant in bucket.acl_grantees:
                                    if (
                                        grant.URI
                                        == "http://acs.amazonaws.com/groups/global/AllUsers"
                                    ):
                                        report.status = "FAIL"
                                        if trail.is_multiregion:
                                            report.status_extended = f"S3 Bucket {trail_bucket} from multiregion trail {trail.name} is publicly accessible."
                                        else:
                                            report.status_extended = f"S3 Bucket {trail_bucket} from single region trail {trail.name} is publicly accessible."
                                        break
                    # check if trail bucket is a cross account bucket
                    if not trail_bucket_is_in_account:
                        report.status = "MANUAL"
                        report.status_extended = f"Trail {trail.name} bucket ({trail_bucket}) is a cross-account bucket in another account out of Prowler's permissions scope, please check it manually."
                    findings.append(report)

        return findings
