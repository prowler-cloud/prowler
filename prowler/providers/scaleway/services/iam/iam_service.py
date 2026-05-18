from typing import Optional

from pydantic.v1 import BaseModel
from scaleway.iam.v1alpha1 import IamV1Alpha1API

from prowler.lib.logger import logger
from prowler.providers.scaleway.lib.service.service import ScalewayService


class IAM(ScalewayService):
    """Scaleway IAM service.

    Loads the users in scope plus every API key tied to the current
    organization. Checks consume the materialized lists; nothing in this
    class is lazy. Each load operation tracks success/failure separately
    so checks can degrade to ``MANUAL`` when data is incomplete instead of
    falsely passing.
    """

    def __init__(self, provider):
        super().__init__("iam", provider)
        self._api = IamV1Alpha1API(self.client)

        # Cached state — populated eagerly during construction
        self.users: list[ScalewayUser] = []
        self.api_keys: list[ScalewayAPIKey] = []

        # Resolved once at authentication time from the audit identity.
        # Deriving it from the user list instead would silently PASS root
        # API keys whenever the user listing comes back empty.
        self.account_root_user_id: Optional[str] = (
            provider.identity.account_root_user_id
        )

        # Load status flags — checks consult these to surface MANUAL when
        # the underlying API call failed rather than reporting empty lists
        # as a clean PASS.
        self.users_loaded: bool = False
        self.api_keys_loaded: bool = False

        self._load_users()
        self._load_api_keys()

    def _load_users(self) -> None:
        """List every IAM user in the audited organization."""
        try:
            users = self._api.list_users_all(organization_id=self.organization_id)
            for user in users:
                self.users.append(
                    ScalewayUser(
                        id=user.id,
                        email=user.email,
                        username=user.username,
                        organization_id=user.organization_id,
                        account_root_user_id=user.account_root_user_id,
                        mfa=bool(getattr(user, "mfa", False)),
                        type_=(
                            str(user.type_) if getattr(user, "type_", None) else None
                        ),
                        status=(
                            str(user.status) if getattr(user, "status", None) else None
                        ),
                    )
                )

            self.users_loaded = True

        except Exception as error:
            logger.error(
                f"{self.service} - Error listing users: "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _load_api_keys(self) -> None:
        """List every API key in the audited organization."""
        try:
            api_keys = self._api.list_api_keys_all(organization_id=self.organization_id)
            for key in api_keys:
                self.api_keys.append(
                    ScalewayAPIKey(
                        access_key=key.access_key,
                        description=key.description,
                        user_id=key.user_id,
                        application_id=key.application_id,
                        default_project_id=key.default_project_id,
                        editable=bool(key.editable),
                        managed=bool(getattr(key, "managed", False)),
                        creation_ip=key.creation_ip,
                        created_at=str(key.created_at) if key.created_at else None,
                        updated_at=str(key.updated_at) if key.updated_at else None,
                        expires_at=str(key.expires_at) if key.expires_at else None,
                    )
                )

            self.api_keys_loaded = True

        except Exception as error:
            logger.error(
                f"{self.service} - Error listing API keys: "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class ScalewayUser(BaseModel):
    """Subset of a Scaleway IAM user surface that the checks need."""

    id: str
    email: Optional[str] = None
    username: Optional[str] = None
    organization_id: Optional[str] = None
    account_root_user_id: Optional[str] = None
    mfa: bool = False
    type_: Optional[str] = None
    status: Optional[str] = None
    # Provide name/id for CheckReportScaleway
    name: str = ""

    def __init__(self, **data):
        super().__init__(**data)
        self.name = self.email or self.username or self.id


class ScalewayAPIKey(BaseModel):
    """Subset of a Scaleway IAM API key surface that the checks need."""

    access_key: str
    description: Optional[str] = None
    user_id: Optional[str] = None
    application_id: Optional[str] = None
    default_project_id: Optional[str] = None
    editable: bool = False
    managed: bool = False
    creation_ip: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    expires_at: Optional[str] = None
    # Provide name/id for CheckReportScaleway
    name: str = ""
    id: str = ""

    def __init__(self, **data):
        super().__init__(**data)
        self.id = self.access_key
        self.name = self.description or self.access_key


class ScalewayIAMDataUnavailable(BaseModel):
    """Stand-in resource used when the IAM service failed to load.

    Lets checks materialize a ``MANUAL`` finding (instead of a silent
    ``PASS``) when users or API keys could not be retrieved.
    ``CheckReportScaleway`` reads ``name``/``id``/``organization_id``/
    ``region`` off the resource, so exposing those is enough.
    """

    organization_id: str
    name: str = "iam-data-unavailable"
    id: str = "iam-data-unavailable"
    region: str = "global"
