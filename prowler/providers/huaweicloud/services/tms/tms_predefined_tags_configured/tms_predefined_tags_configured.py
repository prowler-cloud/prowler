from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.tms.tms_client import tms_client
from prowler.providers.huaweicloud.services.tms.tms_service import (
    PredefinedTagsConfiguration,
)


class tms_predefined_tags_configured(Check):
    """Ensure TMS predefined tags are configured for governance."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        """Execute the TMS predefined tags configuration check.

        Returns:
            list[CheckReportHuaweiCloud]: One PASS or FAIL report when the TMS
                inventory is available.
        """
        if tms_client.predefined_tags is None:
            return []

        resource = PredefinedTagsConfiguration(
            id=f"{tms_client.audited_account}-predefined-tags",
            name="TMS Predefined Tags",
            region=tms_client.region,
            arn=f"huaweicloud:tms:{tms_client.region}:{tms_client.audited_account}:predefined-tags",
            predefined_tags=tms_client.predefined_tags,
        )
        report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=resource)

        if resource.predefined_tags:
            report.status = "PASS"
            report.status_extended = (
                "1 predefined tag is configured."
                if len(resource.predefined_tags) == 1
                else f"{len(resource.predefined_tags)} predefined tags are configured."
            )
        else:
            report.status = "FAIL"
            report.status_extended = "No predefined tags are configured."

        return [report]
