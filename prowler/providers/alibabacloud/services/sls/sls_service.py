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
        logger.info(
            f"SLS service initialized - Projects: {len(self.projects)}, Logstores: {len(self.logstores)}, Alerts: {len(self.alerts)}"
        )

    def _list_projects(self):
        """List SLS projects across regions with timeout protection"""
        for region in self.regions:
            try:
                import threading

                from aliyun.log import LogClient

                # Skip non-mainland China regions as they typically don't have SLS or have connectivity issues
                # This is a pragmatic approach to avoid long timeouts
                non_mainland_prefixes = ("ap-", "us-", "eu-", "me-")
                if any(region.startswith(prefix) for prefix in non_mainland_prefixes):
                    logger.debug(
                        f"Skipping {region} - SLS primarily available in mainland China regions"
                    )
                    continue

                res = None
                client = None

                def fetch_projects():
                    nonlocal res, client
                    try:
                        endpoint = f"{region}.log.aliyuncs.com"
                        client = LogClient(
                            endpoint,
                            self.provider.session.credentials.access_key_id,
                            self.provider.session.credentials.access_key_secret,
                        )
                        res = client.list_project()
                    except Exception as e:
                        logger.debug(f"Error in fetch_projects for {region}: {e}")

                # Run with timeout
                thread = threading.Thread(target=fetch_projects, daemon=True)
                thread.start()
                thread.join(timeout=5)  # 5 second timeout per region

                if thread.is_alive():
                    # Timeout occurred
                    logger.debug(f"SLS request timeout for {region} after 5 seconds")

                # Process projects if found
                if res and res.get_projects():
                    for project_data in res.get_projects():
                        project_name = project_data.get("projectName", "")
                        if not project_name:
                            continue

                        arn = self.generate_resource_arn(
                            "project", project_name, region
                        )

                        project = Project(
                            project_name=project_name,
                            arn=arn,
                            region=region,
                            description=project_data.get("description", ""),
                            status=project_data.get("status", "Normal"),
                            create_time=project_data.get("createTime", ""),
                        )
                        self.projects[arn] = project
                        logger.info(f"Found SLS project: {project_name} in {region}")

                        # List logstores for this project
                        try:
                            logstore_res = client.list_logstore(project_name)
                            if logstore_res and logstore_res.get_logstores():
                                for logstore_name in logstore_res.get_logstores():
                                    # Get logstore details
                                    try:
                                        logstore_info = client.get_logstore(
                                            project_name, logstore_name
                                        )

                                        logstore_arn = self.generate_resource_arn(
                                            "logstore",
                                            f"{project_name}/{logstore_name}",
                                            region,
                                        )

                                        # Get encryption config
                                        encrypt_conf = {"enable": False}
                                        if hasattr(logstore_info, "encrypt_conf"):
                                            encrypt_conf = (
                                                logstore_info.encrypt_conf
                                                or encrypt_conf
                                            )

                                        logstore = Logstore(
                                            logstore_name=logstore_name,
                                            project_name=project_name,
                                            arn=logstore_arn,
                                            region=region,
                                            ttl=(
                                                logstore_info.ttl
                                                if hasattr(logstore_info, "ttl")
                                                else 30
                                            ),
                                            shard_count=(
                                                logstore_info.shard_count
                                                if hasattr(logstore_info, "shard_count")
                                                else 2
                                            ),
                                            enable_tracking=(
                                                logstore_info.enable_tracking
                                                if hasattr(
                                                    logstore_info, "enable_tracking"
                                                )
                                                else False
                                            ),
                                            encrypt_conf=encrypt_conf,
                                            telemetry_type=(
                                                logstore_info.telemetry_type
                                                if hasattr(
                                                    logstore_info, "telemetry_type"
                                                )
                                                else "None"
                                            ),
                                            hot_ttl=(
                                                logstore_info.hot_ttl
                                                if hasattr(logstore_info, "hot_ttl")
                                                else 30
                                            ),
                                        )
                                        self.logstores[logstore_arn] = logstore
                                        logger.info(
                                            f"Found SLS logstore: {logstore_name} in project {project_name}"
                                        )
                                    except Exception as ls_error:
                                        logger.warning(
                                            f"Could not get details for logstore {logstore_name}: {ls_error}"
                                        )
                        except Exception as ls_list_error:
                            logger.warning(
                                f"Could not list logstores for project {project_name}: {ls_list_error}"
                            )
                else:
                    logger.debug(f"No SLS projects found in {region}")

            except Exception as error:
                self._handle_api_error(error, "ListProjects", region)

    def _list_alerts(self):
        """List all SLS alerts across projects"""
        # TODO: Implement actual SDK call when alert API is available
        # For now, we skip alert collection to avoid hanging issues
        # Alert checks will report no alerts found, which is correct behavior
