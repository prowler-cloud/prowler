from unittest import mock

from prowler.providers.scaleway.models import ScalewayIdentityInfo
from prowler.providers.scaleway.services.iam.iam_service import IAM
from tests.providers.scaleway.scaleway_fixtures import (
    APPLICATION_ID,
    MEMBER_USER_ID,
    ORGANIZATION_ID,
    ROOT_USER_ID,
    USER_API_KEY,
    set_mocked_scaleway_provider,
)


def _application_identity() -> ScalewayIdentityInfo:
    """Identity produced by an application-scoped API key: the IAM API
    never exposes account_root_user_id for an application bearer."""
    return ScalewayIdentityInfo(
        organization_id=ORGANIZATION_ID,
        bearer_id=APPLICATION_ID,
        bearer_type="application",
        bearer_email=None,
        account_root_user_id=None,
    )


def _mock_user(
    user_id: str, account_root_user_id: str = ROOT_USER_ID, email: str = "u@example.com"
):
    user = mock.MagicMock()
    user.id = user_id
    user.email = email
    user.username = email.split("@")[0]
    user.organization_id = ORGANIZATION_ID
    user.account_root_user_id = account_root_user_id
    user.mfa = True
    user.type_ = "owner" if user_id == account_root_user_id else "member"
    user.status = "activated"
    return user


def _mock_api_key(access_key: str, user_id: str = None, application_id: str = None):
    key = mock.MagicMock()
    key.access_key = access_key
    key.description = "test"
    key.user_id = user_id
    key.application_id = application_id
    key.default_project_id = None
    key.editable = True
    key.managed = False
    key.creation_ip = None
    key.created_at = None
    key.updated_at = None
    key.expires_at = None
    return key


class Test_IAM_service:
    def test_loads_users_and_api_keys(self):
        provider = set_mocked_scaleway_provider()

        with mock.patch(
            "prowler.providers.scaleway.services.iam.iam_service.IamV1Alpha1API"
        ) as iam_cls:
            api = iam_cls.return_value
            api.list_users_all.return_value = [
                _mock_user(ROOT_USER_ID),
                _mock_user(MEMBER_USER_ID, email="m@example.com"),
            ]
            api.list_api_keys_all.return_value = [
                _mock_api_key(USER_API_KEY, user_id=MEMBER_USER_ID),
                _mock_api_key("SCWAPP", application_id=APPLICATION_ID),
            ]

            iam = IAM(provider)

        assert iam.users_loaded is True
        assert iam.api_keys_loaded is True
        assert iam.account_root_user_id == ROOT_USER_ID
        assert len(iam.users) == 2
        assert len(iam.api_keys) == 2

    def test_marks_users_unloaded_on_error(self):
        provider = set_mocked_scaleway_provider()

        with mock.patch(
            "prowler.providers.scaleway.services.iam.iam_service.IamV1Alpha1API"
        ) as iam_cls:
            api = iam_cls.return_value
            api.list_users_all.side_effect = Exception("denied")
            api.list_api_keys_all.return_value = []

            iam = IAM(provider)

        assert iam.users_loaded is False
        assert iam.api_keys_loaded is True
        # account_root_user_id comes from the audit identity, not the user
        # list, so a failed user listing must not blind the root-key check.
        assert iam.account_root_user_id == ROOT_USER_ID

    def test_application_key_resolves_root_user_from_user_list(self):
        # Application-scoped API key: identity.account_root_user_id is None,
        # so it must be recovered from the loaded user list. Otherwise the
        # root-key check would silently PASS root-owned keys.
        provider = set_mocked_scaleway_provider(identity=_application_identity())

        with mock.patch(
            "prowler.providers.scaleway.services.iam.iam_service.IamV1Alpha1API"
        ) as iam_cls:
            api = iam_cls.return_value
            api.list_users_all.return_value = [
                _mock_user(ROOT_USER_ID),
                _mock_user(MEMBER_USER_ID, email="m@example.com"),
            ]
            api.list_api_keys_all.return_value = []

            iam = IAM(provider)

        assert iam.account_root_user_id == ROOT_USER_ID

    def test_account_root_user_id_none_when_unresolvable(self):
        # Application key + no user record exposes account_root_user_id:
        # nothing to fall back to, so it stays None and the root-key check
        # will degrade to MANUAL downstream.
        provider = set_mocked_scaleway_provider(identity=_application_identity())

        with mock.patch(
            "prowler.providers.scaleway.services.iam.iam_service.IamV1Alpha1API"
        ) as iam_cls:
            api = iam_cls.return_value
            api.list_users_all.return_value = [
                _mock_user(MEMBER_USER_ID, account_root_user_id=None)
            ]
            api.list_api_keys_all.return_value = []

            iam = IAM(provider)

        assert iam.account_root_user_id is None
