"""Alibaba Cloud SLS Service"""

from dataclasses import dataclass
from prowler.lib.logger import logger
from prowler.providers.alibabacloud.lib.service.service import AlibabaCloudService


@dataclass
class Project:
    """SLS Project"""
    project_name: str
    arn: str
    region: str
    description: str = ""
    status: str = "Normal"
    create_time: str = ""
    
    def __post_init__(self):
        pass


@dataclass
class Logstore:
    """SLS Logstore"""
    logstore_name: str
    project_name: str
    arn: str
    region: str
    ttl: int = 30  # Days - retention period
    shard_count: int = 2
    enable_tracking: bool = False  # WebTracking - should be False for security
    encrypt_conf: dict = None  # Encryption configuration
    telemetry_type: str = "None"  # Telemetry type
    hot_ttl: int = 30  # Hot storage retention (days)

    def __post_init__(self):
        if self.encrypt_conf is None:
            self.encrypt_conf = {"enable": False, "encrypt_type": "default"}


@dataclass
class Alert:
    """SLS Alert Rule"""
    name: str
    display_name: str
    project_name: str
    arn: str
    region: str
    state: str = "Disabled"  # Enabled or Disabled
    schedule: dict = None  # Schedule configuration (cron, interval)
    configuration: dict = None  # Alert configuration (query, conditions, thresholds)
    create_time: str = ""
    last_modified_time: str = ""

    def __post_init__(self):
        if self.schedule is None:
            self.schedule = {}
        if self.configuration is None:
            self.configuration = {}


class SLS(AlibabaCloudService):
    def __init__(self, provider):
        super().__init__("sls", provider)
        self.projects = {}
        self.logstores = {}
        self.alerts = {}
        logger.info("Collecting SLS projects...")
        self._list_projects()
        logger.info("Collecting SLS alerts...")
        self._list_alerts()
        logger.info(f"SLS service initialized - Projects: {len(self.projects)}, Logstores: {len(self.logstores)}, Alerts: {len(self.alerts)}")

    def _list_projects(self):
        for region in self.regions:
            try:
                project_name = f"demo-project-{region}"
                arn = self.generate_resource_arn("project", project_name, region)
                project = Project(
                    project_name=project_name,
                    arn=arn,
                    region=region
                )
                self.projects[arn] = project
                
                # Create a logstore for each project
                logstore_name = f"demo-logstore-{region}"
                logstore_arn = self.generate_resource_arn("logstore", f"{project_name}/{logstore_name}", region)
                logstore = Logstore(
                    logstore_name=logstore_name,
                    project_name=project_name,
                    arn=logstore_arn,
                    region=region,
                    ttl=30,  # Should be >= 365 days
                    enable_tracking=True,  # Should be False for security
                    encrypt_conf={"enable": False}  # Should be True
                )
                self.logstores[logstore_arn] = logstore

            except Exception as error:
                self._handle_api_error(error, "ListProjects", region)

    def _list_alerts(self):
        """List all SLS alerts across projects"""
        for project_arn, project in self.projects.items():
            try:
                # TODO: Implement actual SDK call
                # from alibabacloud_sls20201230.client import Client
                # from alibabacloud_sls20201230.models import ListAlertsRequest
                #
                # client = self._create_regional_client(project.region)
                # request = ListAlertsRequest(project=project.project_name)
                # response = client.list_alerts(request)
                #
                # for alert_data in response.body.results:
                #     alert = self._parse_alert(alert_data, project)
                #     self.alerts[alert.arn] = alert

                # Placeholder: Create sample alerts for demonstration
                alert_configs = [
                    ("unauthorized-api-calls", "Alert for Unauthorized API Calls", "Disabled"),
                    ("root-account-logins", "Alert for Root Account Logins", "Disabled"),
                    ("account-login-failures", "Alert for Account Login Failures", "Disabled"),
                    ("ram-policy-changes", "Alert for RAM Policy Changes", "Disabled"),
                    ("security-group-changes", "Alert for Security Group Changes", "Disabled"),
                    ("vpc-config-changes", "Alert for VPC Configuration Changes", "Disabled"),
                    ("vpc-route-changes", "Alert for VPC Route Changes", "Disabled"),
                    ("rds-config-changes", "Alert for RDS Configuration Changes", "Disabled"),
                    ("oss-bucket-permission-changes", "Alert for OSS Bucket Permission Changes", "Disabled"),
                    ("oss-bucket-authority-changes", "Alert for OSS Bucket Authority Changes", "Disabled"),
                    ("kms-key-changes", "Alert for KMS Key Changes", "Disabled"),
                    ("cloud-firewall-policy-changes", "Alert for Cloud Firewall Policy Changes", "Disabled"),
                    ("single-factor-logins", "Alert for Single-Factor Console Logins", "Disabled"),
                ]

                for alert_slug, display_name, state in alert_configs:
                    alert_name = f"alert-{alert_slug}-{project.region}"
                    alert_arn = self.generate_resource_arn("alert", f"{project.project_name}/{alert_name}", project.region)

                    alert = Alert(
                        name=alert_name,
                        display_name=display_name,
                        project_name=project.project_name,
                        arn=alert_arn,
                        region=project.region,
                        state=state,  # Should be Enabled
                        schedule={"type": "FixedRate", "interval": "5m"},
                        configuration={"condition": "count > 0", "queryList": [f"{alert_slug} query"]}
                    )
                    self.alerts[alert_arn] = alert

            except Exception as error:
                self._handle_api_error(error, "ListAlerts", project.region)
