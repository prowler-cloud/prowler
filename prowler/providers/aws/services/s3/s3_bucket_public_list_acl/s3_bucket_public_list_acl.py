from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client
from prowler.providers.aws.services.s3.s3control_client import s3control_client


class s3_bucket_public_list_acl(Check):
    """Ensure S3 bucket ACLs do not let anyone list the bucket.

    - PASS: Public access is blocked, or the ACL grants no public read access.
    - FAIL: The ACL grants AllUsers or AuthenticatedUsers read access.
    - MANUAL: The bucket ACL could not be retrieved (missing permissions) and
      public ACLs are not ignored.
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
                    report.status_extended = (
                        f"S3 Bucket {bucket.name} is not publicly listable."
                    )
                    if not (
                        bucket.public_access_block.ignore_public_acls
                        and bucket.public_access_block.restrict_public_buckets
                    ):
                        if (
                            not bucket.acl_retrieved
                            and not bucket.public_access_block.ignore_public_acls
                        ):
                            report.status = "MANUAL"
                            report.status_extended = f"Cannot evaluate whether S3 Bucket {bucket.name} is publicly listable: the bucket ACL could not be retrieved. Verify that the scanning credentials are allowed to call s3:GetBucketAcl."
                        # 3. If bucket has no public block, check bucket ACL
                        for grantee in bucket.acl_grantees:
                            if grantee.type in "Group":
                                if (
                                    "AllUsers" in grantee.URI
                                    or "AuthenticatedUsers" in grantee.URI
                                ) and (
                                    grantee.permission == "FULL_CONTROL"
                                    or grantee.permission == "READ"
                                    or grantee.permission == "READ_ACP"
                                ):
                                    report.status = "FAIL"
                                    report.status_extended = f"S3 Bucket {bucket.name} is listable by anyone due to the bucket ACL: {grantee.URI.split('/')[-1]} having the {grantee.permission} permission."

                    findings.append(report)
        return findings
