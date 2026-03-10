from typing import List, Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.mongodbatlas.lib.service.service import MongoDBAtlasService
from prowler.providers.mongodbatlas.mongodbatlas_provider import MongodbatlasProvider


class Organizations(MongoDBAtlasService):
    """MongoDB Atlas Organizations service"""

    def __init__(self, provider: MongodbatlasProvider):
        super().__init__(__class__.__name__, provider)
        self.organizations = self._list_organizations()

    def _list_organizations(self):
        """
        List MongoDB Atlas organization for the authenticated API key

        Returns:
            Dict[str, Organization]: Dictionary containing the organization indexed by organization ID
        """
        logger.info("Organizations - Listing MongoDB Atlas organization...")
        organizations = {}

        try:
            # Get the organization associated with the API key
            all_orgs = self._paginate_request("/orgs")

            for org_data in all_orgs:
                org_id = org_data["id"]

                # Get organization settings
                org_settings = {}
                try:
                    org_settings = self._make_request("GET", f"/orgs/{org_id}/settings")
                except Exception as error:
                    logger.error(
                        f"Error getting organization settings for organization {org_id}: {error}"
                    )

                # Create organization object
                organization = Organization(
                    id=org_id,
                    name=org_data.get("name", ""),
                    settings=(
                        OrganizationSettings(
                            api_access_list_required=org_settings.get(
                                "apiAccessListRequired", False
                            ),
                            ip_access_list_enabled=org_settings.get(
                                "ipAccessListEnabled", False
                            ),
                            ip_access_list=org_settings.get("ipAccessList", []),
                            multi_factor_auth_required=org_settings.get(
                                "multiFactorAuthRequired", False
                            ),
                            security_contact=org_settings.get("securityContact"),
                            max_service_account_secret_validity_in_hours=org_settings.get(
                                "maxServiceAccountSecretValidityInHours"
                            ),
                        )
                        if org_settings
                        else None
                    ),
                )

                organizations[org_id] = organization

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        logger.info(f"Found {len(organizations)} MongoDB Atlas organizations")
        return organizations


class OrganizationSettings(BaseModel):
    """MongoDB Atlas Organization Settings model"""

    api_access_list_required: bool = False
    ip_access_list_enabled: bool = False
    ip_access_list: Optional[List[str]] = []
    multi_factor_auth_required: bool = False
    security_contact: Optional[str] = None
    max_service_account_secret_validity_in_hours: Optional[int] = None


class Organization(BaseModel):
    """MongoDB Atlas Organization model"""

    id: str
    name: str
    settings: Optional[OrganizationSettings] = None
    location: str = "global"
