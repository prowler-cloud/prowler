from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.ecs.ecs_client import ecs_client
from prowler.providers.alibabacloud.services.ecs.lib.security_group_port_check import (
    execute_public_port_check,
)

CHECK_PORTS = (9200, 9300, 5601)
SERVICE_NAME = "Elasticsearch and Kibana"


class ecs_securitygroup_restrict_elasticsearch_kibana_internet(Check):
    """Check if security groups restrict Elasticsearch and Kibana from the internet."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        return execute_public_port_check(self, ecs_client, CHECK_PORTS, SERVICE_NAME)
