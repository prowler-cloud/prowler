from typing import List

from prowler.lib.check.models import Check, CheckReportSupabase
from prowler.providers.supabase.services.storage.storage_client import storage_client


class storage_bucket_not_public(Check):
    """Check that Supabase Storage buckets are private.

    Objects in a public bucket are downloadable by anyone who knows the path,
    without any JWT or Row Level Security policy being evaluated.
    """

    def execute(self) -> List[CheckReportSupabase]:
        """Return one finding per bucket."""
        findings = []
        for bucket in storage_client.buckets.values():
            report = CheckReportSupabase(metadata=self.metadata(), resource=bucket)
            if bucket.public:
                report.status = "FAIL"
                report.status_extended = (
                    f"Bucket {bucket.name} in project {bucket.project_name} is public, "
                    f"so every object is downloadable without authentication."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Bucket {bucket.name} in project {bucket.project_name} is private."
                )
            findings.append(report)
        return findings
