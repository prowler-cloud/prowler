from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.ecs.ecs_client import ecs_client
from prowler.providers.alibabacloud.services.ecs.lib.security_group_port_check import (
    execute_public_port_check,
)

CHECK_PORTS = (25, 110, 135, 143, 445, 3000, 4333, 5000, 5500, 8080, 8088)
SERVICE_NAME = "high-risk"


class ecs_securitygroup_restrict_high_risk_ports_internet(Check):
    """Check if security groups restrict high-risk TCP ports from the internet."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        return execute_public_port_check(self, ecs_client, CHECK_PORTS, SERVICE_NAME)
