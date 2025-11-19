from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.oss.oss_client import oss_client


class oss_bucket_referer_whitelist(Check):
    def execute(self):
        findings = []
        for bucket in oss_client.buckets.values():
            report = Check_Report_AlibabaCloud(
                metadata=self.metadata(), resource=bucket
            )
            report.status = "FAIL"
            if bucket.referer_config:
                allow_empty = bucket.referer_config.get("AllowEmpty", True)
                referer_list = bucket.referer_config.get("RefererList", [])
                if allow_empty and (not referer_list or len(referer_list) == 0):
                    report.status_extended = f"OSS bucket {bucket.name} allows empty referers and has no referer whitelist."
                elif allow_empty:
                    report.status_extended = (
                        f"OSS bucket {bucket.name} allows empty referers."
                    )
                elif not referer_list or len(referer_list) == 0:
                    report.status_extended = (
                        f"OSS bucket {bucket.name} has no referer whitelist configured."
                    )
                else:
                    report.status = "PASS"
                    report.status_extended = f"OSS bucket {bucket.name} has proper referer whitelist configuration."
            else:
                report.status_extended = (
                    f"OSS bucket {bucket.name} has no referer configuration."
                )
            findings.append(report)
        return findings
