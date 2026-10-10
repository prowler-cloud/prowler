from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.ecs.ecs_client import ecs_client
from prowler.providers.alibabacloud.services.ecs.lib.security_group_port_check import (
    execute_public_port_check,
)

CHECK_PORTS = (1521, 2483)
SERVICE_NAME = "Oracle Database"


class ecs_securitygroup_restrict_oracle_internet(Check):
    """Check if security groups restrict Oracle Database from the internet."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        return execute_public_port_check(self, ecs_client, CHECK_PORTS, SERVICE_NAME)
