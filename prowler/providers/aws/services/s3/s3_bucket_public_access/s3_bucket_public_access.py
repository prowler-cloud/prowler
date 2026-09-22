from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import is_policy_public
from prowler.providers.aws.services.s3.s3_client import s3_client
from prowler.providers.aws.services.s3.s3control_client import s3control_client


class s3_bucket_public_access(Check):
    """Ensure S3 buckets are not publicly accessible through their ACL or policy.

    - PASS: Public access is blocked at account level, or the bucket's public
      access block, ACL and policy grant no public access.
    - FAIL: The bucket ACL or policy grants public access.
    - MANUAL: The bucket ACL or policy could not be retrieved (missing
      permissions) and the data that was read shows no public access.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Evaluate the check.

        Returns:
            list[Check_Report_AWS]: One report per bucket with a public access block, or one
            account-level report when public access is blocked for the account.
        """
        findings = []
        # 1. Check if public buckets are restricted at account level
        if (
            s3control_client.account_public_access_block
            and s3control_client.account_public_access_block.ignore_public_acls
            and s3control_client.account_public_access_block.restrict_public_buckets
        ):
            report = Check_Report_AWS(
                metadata=self.metadata(),
                resource=s3control_client.account_public_access_block,
            )
            report.status = "PASS"
            report.status_extended = "All S3 public access blocked at account level."
            report.region = s3control_client.region
            report.resource_id = s3_client.audited_account
            report.resource_arn = s3_client.account_arn_template
            findings.append(report)
        else:
            # 2. If public access is not blocked at account level, check it at each bucket level
            for bucket in s3_client.buckets.values():
                if bucket.public_access_block:
                    report = Check_Report_AWS(metadata=self.metadata(), resource=bucket)
                    report.status = "PASS"
                    report.status_extended = f"S3 Bucket {bucket.name} is not public."
                    if not (
                        bucket.public_access_block.ignore_public_acls
                        and bucket.public_access_block.restrict_public_buckets
                    ):
                        # 3. If bucket has no public block, check bucket ACL
                        for grantee in bucket.acl_grantees:
                            if grantee.type in "Group":
                                if (
                                    "AllUsers" in grantee.URI
                                    or "AuthenticatedUsers" in grantee.URI
                                ):
                                    report.status = "FAIL"
                                    report.status_extended = f"S3 Bucket {bucket.name} has public access due to bucket ACL."

                        # 4. Check bucket policy
                        if bucket.policy is not None and is_policy_public(
                            bucket.policy, s3_client.audited_account
                        ):
                            report.status = "FAIL"
                            report.status_extended = f"S3 Bucket {bucket.name} has public access due to bucket policy."

                        # 5. A PASS cannot be asserted if the ACL or policy could not be read
                        if report.status == "PASS":
                            missing = []
                            if not bucket.acl_retrieved:
                                missing.append(("ACL", "s3:GetBucketAcl"))
                            if bucket.policy is None:
                                missing.append(("policy", "s3:GetBucketPolicy"))
                            if missing:
                                report.status = "MANUAL"
                                report.status_extended = f"Cannot evaluate public access for S3 Bucket {bucket.name}: the bucket {' and '.join(name for name, _ in missing)} could not be retrieved. Verify that the scanning credentials are allowed to call {' and '.join(action for _, action in missing)}."
                    findings.append(report)
        return findings
