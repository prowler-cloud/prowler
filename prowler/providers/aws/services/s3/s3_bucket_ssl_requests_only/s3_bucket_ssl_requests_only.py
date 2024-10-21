import json
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client

class s3_bucket_ssl_requests_only(Check):
    def execute(self):
        findings = []
        for bucket in s3_client.buckets.values():
            report = Check_Report_AWS(self.metadata())
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_tags = bucket.tags

            # Construct ARN (Amazon Resource Name) from bucket name
            bucket_arn = f"arn:aws:s3:::{bucket.name}"
            report.resource_arn = bucket_arn

            try:
                # Fetch the bucket policy
                bucket_policy = s3_client.client.get_bucket_policy(Bucket=bucket.name)
                policy = json.loads(bucket_policy['Policy'])
                ssl_requests_only = False

                # Check the bucket policy for the condition that enforces SSL requests
                for statement in policy.get('Statement', []):
                    if (statement['Effect'] == 'Deny' and 
                        'aws:SecureTransport' in statement.get('Condition', {}).get('Bool', {})):
                        if statement['Condition']['Bool']['aws:SecureTransport'] == 'false':
                            ssl_requests_only = True
                            break
                
                if ssl_requests_only:
                    report.status = "PASS"
                    report.status_extended = f"S3 Bucket {bucket.name} is configured to accept only SSL requests."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"S3 Bucket {bucket.name} is not configured to accept only SSL requests."
            except Exception as e:
                report.status = "FAIL"
                report.status_extended = f"Failed to check SSL requests only for bucket {bucket.name} due to an error: {str(e)}"

            findings.append(report)
        return findings
