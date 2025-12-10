from typing import Optional

from pydantic.v1 import BaseModel, Field


class OpenStackSession(BaseModel):
    """Holds the authentication/session data used to talk with OpenStack."""

    auth_url: str
    identity_api_version: str = Field(default="3")
    username: str
    password: str
    project_id: str
    region_name: str
    user_domain_name: str = Field(default="Default")
    project_domain_name: str = Field(default="Default")

    def as_sdk_config(self) -> dict:
        """Return a dict compatible with openstacksdk.connect()."""
        return {
            "auth_url": self.auth_url,
            "username": self.username,
            "password": self.password,
            "project_id": self.project_id,
            "region_name": self.region_name,
            "project_domain_name": self.project_domain_name,
            "user_domain_name": self.user_domain_name,
            "identity_api_version": self.identity_api_version,
        }


class OpenStackIdentityInfo(BaseModel):
    """Represents the identity used during the audit run."""

    user_id: Optional[str] = None
    username: str
    project_id: str
    project_name: Optional[str] = None
    region_name: str
    user_domain_name: str
    project_domain_name: str
