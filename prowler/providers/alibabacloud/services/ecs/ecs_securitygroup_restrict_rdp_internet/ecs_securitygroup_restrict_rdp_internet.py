from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.ecs.ecs_client import ecs_client
from prowler.providers.alibabacloud.services.ecs.lib.security_group_port_check import (
    execute_public_port_check,
)

CHECK_PORTS = (3389,)


class ecs_securitygroup_restrict_rdp_internet(Check):
    """Check if security groups restrict RDP (port 3389) access from the internet."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        return execute_public_port_check(self, ecs_client, CHECK_PORTS, "Microsoft RDP")
