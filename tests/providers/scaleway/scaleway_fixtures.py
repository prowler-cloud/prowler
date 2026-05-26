from unittest.mock import MagicMock

from prowler.providers.scaleway.models import (
    ScalewayIdentityInfo,
    ScalewaySession,
)
from prowler.providers.scaleway.services.iam.iam_service import (
    ScalewayAPIKey,
    ScalewayUser,
)

# Scaleway Identity
ORGANIZATION_ID = "b4ce0bfc-38fc-4c53-8757-548be64add26"
ROOT_USER_ID = "00000000-0000-0000-0000-000000000001"
MEMBER_USER_ID = "00000000-0000-0000-0000-000000000002"
APPLICATION_ID = "00000000-0000-0000-0000-000000000003"
BEARER_EMAIL = "pedro@prowler.com"

# Scaleway Credentials
ACCESS_KEY = "SCWAE000000000000000"
SECRET_KEY = "00000000-0000-0000-0000-000000000000"

# API Key Constants
ROOT_API_KEY = "SCWROOT00000000000000"
USER_API_KEY = "SCWUSER00000000000000"
APP_API_KEY = "SCWAPP000000000000000"


def set_mocked_scaleway_provider(
    access_key: str = ACCESS_KEY,
    secret_key: str = SECRET_KEY,
    identity: ScalewayIdentityInfo = None,
    audit_config: dict = None,
):
    """Create a mocked ScalewayProvider for testing."""
    provider = MagicMock()
    provider.type = "scaleway"
    provider.session = ScalewaySession(
        access_key=access_key,
        secret_key=secret_key,
        organization_id=ORGANIZATION_ID,
        default_project_id=None,
        default_region="fr-par",
        client=MagicMock(),
    )
    provider.identity = identity or ScalewayIdentityInfo(
        organization_id=ORGANIZATION_ID,
        bearer_id=ROOT_USER_ID,
        bearer_type="user",
        bearer_email=BEARER_EMAIL,
        account_root_user_id=ROOT_USER_ID,
    )
    provider.audit_config = audit_config or {}
    provider.fixer_config = {}

    return provider


def make_user(
    user_id: str = ROOT_USER_ID,
    email: str = BEARER_EMAIL,
    account_root_user_id: str = ROOT_USER_ID,
    mfa: bool = True,
) -> ScalewayUser:
    return ScalewayUser(
        id=user_id,
        email=email,
        username=email.split("@")[0] if email else None,
        organization_id=ORGANIZATION_ID,
        account_root_user_id=account_root_user_id,
        mfa=mfa,
        type_="owner" if user_id == account_root_user_id else "member",
        status="activated",
    )


def make_api_key(
    access_key: str = USER_API_KEY,
    user_id: str = MEMBER_USER_ID,
    application_id: str = None,
    description: str = "test key",
    expires_at: str = None,
) -> ScalewayAPIKey:
    return ScalewayAPIKey(
        access_key=access_key,
        description=description,
        user_id=user_id,
        application_id=application_id,
        default_project_id=None,
        editable=True,
        managed=False,
        creation_ip=None,
        created_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:00Z",
        expires_at=expires_at,
    )
