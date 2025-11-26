from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.config import DEFAULT_RETRY_ATTEMPTS
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.lib.service.service import GCPService


class CloudResourceManager(GCPService):
    def __init__(self, provider: GcpProvider):
        super().__init__(__class__.__name__, provider)

        self.bindings = []
        self.cloud_resource_manager_projects = []
        self.organizations = []
        self._get_iam_policy()
        self._get_organizations()

    def _get_iam_policy(self):
        for project_id in self.project_ids:
            try:
                # Get project details to obtain project number
                project_details = (
                    self.client.projects()
                    .get(projectId=project_id)
                    .execute(num_retries=DEFAULT_RETRY_ATTEMPTS)
                )
                project_number = project_details.get("projectNumber", "")

                policy = (
                    self.client.projects()
                    .getIamPolicy(resource=project_id)
                    .execute(num_retries=DEFAULT_RETRY_ATTEMPTS)
                )
                audit_logging = False
                audit_configs = []
                if policy.get("auditConfigs"):
                    audit_logging = True
                    for config in policy.get("auditConfigs", []):
                        log_types = []
                        for log_config in config.get("auditLogConfigs", []):
                            log_types.append(log_config.get("logType", ""))
                        audit_configs.append(
                            AuditConfig(
                                service=config.get("service", ""),
                                log_types=log_types,
                            )
                        )
                self.cloud_resource_manager_projects.append(
                    Project(
                        id=project_id,
                        number=project_number,
                        audit_logging=audit_logging,
                        audit_configs=audit_configs,
                    )
                )
                for binding in policy["bindings"]:
                    self.bindings.append(
                        Binding(
                            role=binding["role"],
                            members=binding["members"],
                            project_id=project_id,
                        )
                    )
            except Exception as error:
                logger.error(
                    f"{self.region} -- "
                    f"{error.__class__.__name__}"
                    f"[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_organizations(self):
        try:
            if self.project_ids:
                response = (
                    self.client.organizations()
                    .search()
                    .execute(num_retries=DEFAULT_RETRY_ATTEMPTS)
                )
                for org in response.get("organizations", []):
                    self.organizations.append(
                        Organization(
                            id=org["name"].split("/")[-1],
                            name=org["displayName"],
                        )
                    )
        except Exception as error:
            logger.error(
                f"{self.region} -- "
                f"{error.__class__.__name__}"
                f"[{error.__traceback__.tb_lineno}]: {error}"
            )


class AuditConfig(BaseModel):
    service: str
    log_types: list[str]


class Binding(BaseModel):
    role: str
    members: list
    project_id: str


class Project(BaseModel):
    id: str
    number: str = ""
    audit_logging: bool
    audit_configs: list[AuditConfig] = []


class Organization(BaseModel):
    id: str
    name: str
