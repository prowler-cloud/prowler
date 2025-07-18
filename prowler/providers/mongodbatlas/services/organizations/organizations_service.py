from typing import Dict, Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.mongodbatlas.lib.service.service import MongoDBAtlasService


class Organization(BaseModel):
    """MongoDB Atlas Organization model"""

    id: str
    name: str
    settings: Optional[dict] = {}


class Organizations(MongoDBAtlasService):
    """MongoDB Atlas Organizations service"""

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.organizations = self._list_organizations()

    def _list_organizations(self) -> Dict[str, Organization]:
        """
        List all MongoDB Atlas organizations

        Returns:
            Dict[str, Organization]: Dictionary of organizations indexed by organization ID
        """
        logger.info("Organizations - Listing MongoDB Atlas organizations...")
        organizations = {}

        try:
            # If organization_id filter is set, only get that organization
            if self.provider.organization_id:
                org_data = self._make_request(
                    "GET", f"/orgs/{self.provider.organization_id}"
                )
                organizations[org_data["id"]] = self._process_organization(org_data)
            else:
                # Get all organizations with pagination
                all_orgs = self._paginate_request("/orgs")

                for org_data in all_orgs:
                    organizations[org_data["id"]] = self._process_organization(org_data)

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        logger.info(f"Found {len(organizations)} MongoDB Atlas organizations")
        return organizations

    def _process_organization(self, org_data: dict) -> Organization:
        """
        Process a single organization and fetch additional details

        Args:
            org_data: Raw organization data from API

        Returns:
            Organization: Processed organization object
        """
        org_id = org_data["id"]

        # Get organization settings
        org_settings = self._get_organization_settings(org_id)

        return Organization(
            id=org_id,
            name=org_data.get("name", ""),
            settings=org_settings,
        )

    def _get_organization_settings(self, org_id: str) -> dict:
        """
        Get organization settings

        Args:
            org_id: Organization ID

        Returns:
            dict: Organization settings
        """
        try:
            settings = self._make_request("GET", f"/orgs/{org_id}/settings")
            return settings
        except Exception as error:
            logger.error(
                f"Error getting organization settings for organization {org_id}: {error}"
            )
            return {}
