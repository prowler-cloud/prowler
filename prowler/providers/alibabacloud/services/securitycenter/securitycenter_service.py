from alibabacloud_sas20181203 import models as sas_models
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.alibabacloud.lib.service.service import AlibabaCloudService


class SecurityCenter(AlibabaCloudService):
    """
    Security Center service class for Alibaba Cloud.

    This class provides methods to interact with Alibaba Cloud Security Center
    to retrieve vulnerabilities, agent status, etc.
    """

    def __init__(self, provider):
        # Call AlibabaCloudService's __init__
        super().__init__("sas", provider, global_service=True)

        self.instance_vulnerabilities = {}
        self.instance_agents = {}
        self.uninstalled_machines = []
        self.notice_configs = {}
        self.vul_configs = {}
        self.concern_necessity = []
        self.edition = None
        self.version = None
        self._describe_vulnerabilities()
        self._describe_agents()
        self._list_uninstalled_machines()
        self._describe_notice_configs()
        self._describe_vul_config()
        self._describe_concern_necessity()
        self._get_edition()

    def _describe_vulnerabilities(self):
        """List vulnerabilities for ECS instances."""
        logger.info("Security Center - Describing Vulnerabilities...")

        try:
            # Get all vulnerabilities
            # Type: "cve" for CVE vulnerabilities, "app" for application vulnerabilities, "sys" for system vulnerabilities
            # We'll check all types by making separate requests
            vulnerability_types = ["cve", "app", "sys"]

            for vul_type in vulnerability_types:
                request = sas_models.DescribeVulListRequest()
                request.type = vul_type
                request.current_page = 1
                request.page_size = 100

                while True:
                    response = self.client.describe_vul_list(request)

                    if response and response.body and response.body.vul_records:
                        vul_records = response.body.vul_records
                        if not vul_records:
                            break

                        for vul_record in vul_records:
                            instance_id = getattr(vul_record, "instance_id", "")
                            if not instance_id:
                                continue

                            # Get instance name and region from the vulnerability record
                            instance_name = getattr(
                                vul_record, "instance_name", instance_id
                            )
                            region = getattr(vul_record, "region_id", "")

                            instance_key = (
                                f"{region}:{instance_id}" if region else instance_id
                            )

                            if instance_key not in self.instance_vulnerabilities:
                                self.instance_vulnerabilities[instance_key] = (
                                    InstanceVulnerability(
                                        instance_id=instance_id,
                                        instance_name=instance_name,
                                        region=region,
                                        has_vulnerabilities=True,
                                        vulnerability_count=1,
                                    )
                                )
                            else:
                                # Increment vulnerability count
                                self.instance_vulnerabilities[
                                    instance_key
                                ].vulnerability_count += 1

                        # Check if there are more pages
                        total_count = getattr(response.body, "total_count", 0)
                        if request.current_page * request.page_size >= total_count:
                            break
                        request.current_page += 1
                    else:
                        break

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_agents(self):
        """List Security Center agent status for ECS instances."""
        logger.info("Security Center - Describing Agents...")

        try:
            # Get all agents
            request = sas_models.DescribeCloudCenterInstancesRequest()
            request.current_page = 1
            request.page_size = 100

            while True:
                response = self.client.describe_cloud_center_instances(request)

                if response and response.body and response.body.instances:
                    instances = response.body.instances
                    if not instances:
                        break

                    for instance_data in instances:
                        instance_id = getattr(instance_data, "instance_id", "")
                        if not instance_id:
                            continue

                        instance_name = getattr(
                            instance_data, "instance_name", instance_id
                        )
                        region = getattr(instance_data, "region_id", "")
                        agent_status = getattr(instance_data, "client_status", "")

                        # Determine if agent is installed and online
                        agent_installed = agent_status in ["online", "offline"]
                        is_online = agent_status == "online"

                        instance_key = (
                            f"{region}:{instance_id}" if region else instance_id
                        )

                        self.instance_agents[instance_key] = InstanceAgent(
                            instance_id=instance_id,
                            instance_name=instance_name,
                            region=region,
                            agent_installed=agent_installed,
                            agent_status=(
                                agent_status
                                if agent_status
                                else ("online" if is_online else "not_installed")
                            ),
                        )

                    # Check if there are more pages
                    total_count = getattr(response.body, "total_count", 0)
                    if request.current_page * request.page_size >= total_count:
                        break
                    request.current_page += 1
                else:
                    break

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_uninstalled_machines(self):
        """List machines without Security Center agent installed."""
        logger.info("Security Center - Listing Uninstalled Machines...")

        try:
            # Get all machines without agent installed
            request = sas_models.ListUninstallAegisMachinesRequest()
            request.current_page = 1
            request.page_size = 100

            while True:
                response = self.client.list_uninstall_aegis_machines(request)

                if response and response.body and response.body.machine_list:
                    machines = response.body.machine_list
                    if not machines:
                        break

                    for machine_data in machines:
                        instance_id = getattr(machine_data, "instance_id", "")
                        if not instance_id:
                            continue

                        self.uninstalled_machines.append(
                            UninstalledMachine(
                                instance_id=instance_id,
                                instance_name=getattr(
                                    machine_data, "instance_name", instance_id
                                ),
                                region=getattr(machine_data, "region_id", "")
                                or getattr(machine_data, "machine_region", ""),
                                uuid=getattr(machine_data, "uuid", ""),
                                os=getattr(machine_data, "os", ""),
                                internet_ip=getattr(machine_data, "internet_ip", ""),
                                intranet_ip=getattr(machine_data, "intranet_ip", ""),
                            )
                        )

                    # Check if there are more pages
                    total_count = getattr(response.body, "total_count", 0)
                    if request.current_page * request.page_size >= total_count:
                        break
                    request.current_page += 1
                else:
                    break

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_notice_configs(self):
        """List notification configurations for Security Center."""
        logger.info("Security Center - Describing Notice Configs...")

        try:
            # Get notification configurations
            request = sas_models.DescribeNoticeConfigRequest()
            response = self.client.describe_notice_config(request)

            if response and response.body and response.body.notice_config_list:
                notice_configs = response.body.notice_config_list

                for config_data in notice_configs:
                    project = getattr(config_data, "project", "")
                    if not project:
                        continue

                    route = getattr(config_data, "route", 0)
                    time_limit = getattr(config_data, "time_limit", 0)

                    self.notice_configs[project] = NoticeConfig(
                        project=project,
                        route=route,
                        time_limit=time_limit,
                        notification_enabled=route != 0,
                    )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_vul_config(self):
        """List vulnerability scan configuration."""
        logger.info("Security Center - Describing Vulnerability Config...")

        try:
            # Get vulnerability scan configuration
            request = sas_models.DescribeVulConfigRequest()
            response = self.client.describe_vul_config(request)

            if response and response.body and response.body.target_configs:
                target_configs = response.body.target_configs

                for config_data in target_configs:
                    config_type = getattr(config_data, "type", "")
                    config_value = getattr(config_data, "config", "")

                    if config_type:
                        self.vul_configs[config_type] = VulConfig(
                            type=config_type,
                            config=config_value,
                            enabled=config_value != "off",
                        )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_concern_necessity(self):
        """List vulnerability scan level priorities."""
        logger.info("Security Center - Describing Concern Necessity...")

        try:
            # Get vulnerability scan level priorities
            request = sas_models.DescribeConcernNecessityRequest()
            response = self.client.describe_concern_necessity(request)

            if response and response.body:
                concern_necessity = getattr(response.body, "concern_necessity", [])
                if concern_necessity:
                    self.concern_necessity = concern_necessity
                else:
                    self.concern_necessity = []

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            self.concern_necessity = []

    def _get_edition(self):
        """Get Security Center edition."""
        logger.info("Security Center - Getting Edition...")

        # Version mapping: 1=Basic, 3=Enterprise, 5=Advanced, 6=Anti-virus, 7=Ultimate, 8=Multi-Version, 10=Value-added Plan
        version_to_edition = {
            1: "Basic",
            3: "Enterprise",
            5: "Advanced",
            6: "Anti-virus",
            7: "Ultimate",
            8: "Multi-Version",
            10: "Value-added Plan",
        }

        try:
            # Get Security Center edition
            request = sas_models.DescribeVersionConfigRequest()
            response = self.client.describe_version_config(request)

            if response and response.body:
                # Get Version field from response
                version = getattr(response.body, "version", None)

                if version is not None:
                    # Map version number to edition name
                    self.edition = version_to_edition.get(
                        version, f"Unknown (Version {version})"
                    )
                    self.version = version
                    logger.info(
                        f"Security Center Version: {version}, Edition: {self.edition}"
                    )
                else:
                    self.edition = "Unknown"
                    self.version = None
            else:
                self.edition = "Unknown"
                self.version = None

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            self.edition = "Unknown"
            self.version = None


# Models for Security Center service
class InstanceVulnerability(BaseModel):
    """Security Center Instance Vulnerability model."""

    instance_id: str
    instance_name: str
    region: str
    has_vulnerabilities: bool
    vulnerability_count: int = 0


class InstanceAgent(BaseModel):
    """Security Center Instance Agent model."""

    instance_id: str
    instance_name: str
    region: str
    agent_installed: bool
    agent_status: str = ""  # "online", "offline", "not_installed"


class UninstalledMachine(BaseModel):
    """Security Center Uninstalled Machine model."""

    instance_id: str
    instance_name: str
    region: str
    uuid: str = ""
    os: str = ""
    internet_ip: str = ""
    intranet_ip: str = ""


class NoticeConfig(BaseModel):
    """Security Center Notice Config model."""

    project: str
    route: int  # 0 = no notification, >0 = notification enabled
    time_limit: int = 0
    notification_enabled: bool


class VulConfig(BaseModel):
    """Security Center Vulnerability Config model."""

    type: str  # yum, cve, sys, cms, emg, etc.
    config: str  # "off", "on", or other values
    enabled: bool  # True if config != "off"
