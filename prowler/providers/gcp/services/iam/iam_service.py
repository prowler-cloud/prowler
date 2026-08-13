from datetime import datetime

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.config import DEFAULT_RETRY_ATTEMPTS
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.lib.service.service import GCPService
from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_client import (
    cloudresourcemanager_client,
)


class IAM(GCPService):
    def __init__(self, provider: GcpProvider):
        super().__init__(__class__.__name__, provider)
        self.service_accounts = []
        self._get_service_accounts()
        self._get_service_accounts_keys()
        self.workload_identity_pool_providers = []
        self._get_workload_identity_pool_providers()

    def _get_service_accounts(self):
        for project_id in self.project_ids:
            try:
                request = (
                    self.client.projects()
                    .serviceAccounts()
                    .list(name="projects/" + project_id)
                )
                while request is not None:
                    response = request.execute(num_retries=DEFAULT_RETRY_ATTEMPTS)

                    for account in response.get("accounts", []):
                        self.service_accounts.append(
                            ServiceAccount(
                                name=account["name"],
                                email=account["email"],
                                display_name=account.get("displayName", ""),
                                project_id=project_id,
                                uniqueId=account.get("uniqueId", ""),
                                disabled=account.get("disabled", False),
                            )
                        )

                    request = (
                        self.client.projects()
                        .serviceAccounts()
                        .list_next(previous_request=request, previous_response=response)
                    )
            except Exception as error:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_service_accounts_keys(self):
        try:
            for sa in self.service_accounts:
                request = (
                    self.client.projects()
                    .serviceAccounts()
                    .keys()
                    .list(
                        name="projects/"
                        + sa.project_id
                        + "/serviceAccounts/"
                        + sa.email
                    )
                )
                response = request.execute(num_retries=DEFAULT_RETRY_ATTEMPTS)

                for key in response.get("keys", []):
                    sa.keys.append(
                        Key(
                            name=key["name"].split("/")[-1],
                            origin=key["keyOrigin"],
                            type=key["keyType"],
                            valid_after=datetime.strptime(
                                key["validAfterTime"], "%Y-%m-%dT%H:%M:%SZ"
                            ),
                            valid_before=datetime.strptime(
                                key["validBeforeTime"], "%Y-%m-%dT%H:%M:%SZ"
                            ),
                        )
                    )

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_workload_identity_pool_providers(self):
        for project_id in self.project_ids:
            try:
                pools_request = (
                    self.client.projects()
                    .locations()
                    .workloadIdentityPools()
                    .list(parent=f"projects/{project_id}/locations/global")
                )
                while pools_request is not None:
                    pools_response = pools_request.execute(
                        num_retries=DEFAULT_RETRY_ATTEMPTS
                    )
                    for pool in pools_response.get("workloadIdentityPools", []):
                        self._get_providers_for_pool(project_id, pool)
                    pools_request = (
                        self.client.projects()
                        .locations()
                        .workloadIdentityPools()
                        .list_next(
                            previous_request=pools_request,
                            previous_response=pools_response,
                        )
                    )
            except Exception as error:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_providers_for_pool(self, project_id, pool):
        try:
            pool_name = pool.get("name", "")
            pool_id = pool_name.split("/")[-1]
            # A provider can remain ACTIVE while its parent pool is disabled or
            # soft-deleted; a disabled pool cannot vend credentials, so the
            # pool's effective availability must travel with the provider.
            pool_disabled = (
                pool.get("disabled", False) or pool.get("state", "ACTIVE") != "ACTIVE"
            )
            request = (
                self.client.projects()
                .locations()
                .workloadIdentityPools()
                .providers()
                .list(parent=pool_name)
            )
            while request is not None:
                response = request.execute(num_retries=DEFAULT_RETRY_ATTEMPTS)
                for provider in response.get("workloadIdentityPoolProviders", []):
                    provider_type = next(
                        (
                            key
                            for key in ("oidc", "aws", "saml", "x509")
                            if key in provider
                        ),
                        "",
                    )
                    self.workload_identity_pool_providers.append(
                        WorkloadIdentityPoolProvider(
                            name=provider.get("name", ""),
                            id=provider.get("name", "").split("/")[-1],
                            pool_id=pool_id,
                            pool_disabled=pool_disabled,
                            project_id=project_id,
                            state=provider.get("state", ""),
                            disabled=provider.get("disabled", False),
                            attribute_condition=provider.get("attributeCondition", ""),
                            attribute_mapping=provider.get("attributeMapping", {})
                            or {},
                            provider_type=provider_type,
                            issuer_uri=(provider.get("oidc", {}) or {}).get(
                                "issuerUri", ""
                            ),
                            display_name=provider.get("displayName", ""),
                        )
                    )
                request = (
                    self.client.projects()
                    .locations()
                    .workloadIdentityPools()
                    .providers()
                    .list_next(previous_request=request, previous_response=response)
                )
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Key(BaseModel):
    name: str
    origin: str
    type: str
    valid_after: datetime
    valid_before: datetime


class ServiceAccount(BaseModel):
    name: str
    email: str
    display_name: str
    keys: list[Key] = []
    project_id: str
    uniqueId: str
    disabled: bool = False


class WorkloadIdentityPoolProvider(BaseModel):
    """Represent a GCP Workload Identity Federation pool provider."""

    name: str
    id: str
    pool_id: str
    # True when the parent pool is disabled or not ACTIVE; such a pool cannot
    # vend credentials regardless of the provider's own state.
    pool_disabled: bool = False
    project_id: str
    state: str = ""
    disabled: bool = False
    attribute_condition: str = ""
    attribute_mapping: dict = {}
    provider_type: str = ""
    issuer_uri: str = ""
    display_name: str = ""


class AccessApproval(GCPService):
    def __init__(self, provider: GcpProvider):
        super().__init__(__class__.__name__, provider)
        self.settings = {}
        self._get_settings()

    def _get_settings(self):
        for project_id in self.project_ids:
            try:
                response = (
                    self.client.projects().getAccessApprovalSettings(
                        name=f"projects/{project_id}/accessApprovalSettings"
                    )
                ).execute(num_retries=DEFAULT_RETRY_ATTEMPTS)
                self.settings[project_id] = Setting(
                    name=response["name"],
                    project_id=project_id,
                )

            except Exception as error:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class Setting(BaseModel):
    name: str
    project_id: str


class EssentialContacts(GCPService):
    def __init__(self, provider: GcpProvider):
        super().__init__(__class__.__name__, provider)
        self.organizations = []
        self._get_contacts()

    def _get_contacts(self):
        for org in cloudresourcemanager_client.organizations:
            try:
                contacts = False
                response = (
                    self.client.organizations()
                    .contacts()
                    .list(parent="organizations/" + org.id)
                ).execute(num_retries=DEFAULT_RETRY_ATTEMPTS)
                if len(response.get("contacts", [])) > 0:
                    contacts = True

                self.organizations.append(
                    Organization(
                        name=org.name,
                        id=org.id,
                        contacts=contacts,
                    )
                )
            except Exception as error:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class Organization(BaseModel):
    name: str
    id: str
    contacts: bool
