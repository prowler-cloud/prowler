from unittest import mock

from tests.providers.scaleway.scaleway_fixtures import (
    APP_API_KEY,
    APPLICATION_ID,
    MEMBER_USER_ID,
    ORGANIZATION_ID,
    ROOT_API_KEY,
    ROOT_USER_ID,
    USER_API_KEY,
    make_api_key,
    set_mocked_scaleway_provider,
)


def _patch_clients(iam_client_mock):
    """Patch both the provider and the iam_client singleton."""
    return [
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_scaleway_provider(),
        ),
        mock.patch(
            "prowler.providers.scaleway.services.iam.iam_no_root_api_keys.iam_no_root_api_keys.iam_client",
            new=iam_client_mock,
        ),
    ]


class Test_iam_no_root_api_keys:
    def test_no_api_keys_returns_empty_findings(self):
        iam_client = mock.MagicMock()
        iam_client.users_loaded = True
        iam_client.api_keys_loaded = True
        iam_client.account_root_user_id = ROOT_USER_ID
        iam_client.api_keys = []
        iam_client.organization_id = ORGANIZATION_ID

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_scaleway_provider(),
            ),
            mock.patch(
                "prowler.providers.scaleway.services.iam.iam_no_root_api_keys.iam_no_root_api_keys.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.scaleway.services.iam.iam_no_root_api_keys.iam_no_root_api_keys import (
                iam_no_root_api_keys,
            )

            result = iam_no_root_api_keys().execute()
            assert result == []

    def test_root_api_key_fails(self):
        iam_client = mock.MagicMock()
        iam_client.users_loaded = True
        iam_client.api_keys_loaded = True
        iam_client.account_root_user_id = ROOT_USER_ID
        iam_client.api_keys = [
            make_api_key(access_key=ROOT_API_KEY, user_id=ROOT_USER_ID)
        ]
        iam_client.organization_id = ORGANIZATION_ID

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_scaleway_provider(),
            ),
            mock.patch(
                "prowler.providers.scaleway.services.iam.iam_no_root_api_keys.iam_no_root_api_keys.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.scaleway.services.iam.iam_no_root_api_keys.iam_no_root_api_keys import (
                iam_no_root_api_keys,
            )

            result = iam_no_root_api_keys().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == ROOT_API_KEY
            assert ROOT_USER_ID in result[0].status_extended

    def test_user_api_key_passes(self):
        iam_client = mock.MagicMock()
        iam_client.users_loaded = True
        iam_client.api_keys_loaded = True
        iam_client.account_root_user_id = ROOT_USER_ID
        iam_client.api_keys = [
            make_api_key(access_key=USER_API_KEY, user_id=MEMBER_USER_ID)
        ]
        iam_client.organization_id = ORGANIZATION_ID

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_scaleway_provider(),
            ),
            mock.patch(
                "prowler.providers.scaleway.services.iam.iam_no_root_api_keys.iam_no_root_api_keys.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.scaleway.services.iam.iam_no_root_api_keys.iam_no_root_api_keys import (
                iam_no_root_api_keys,
            )

            result = iam_no_root_api_keys().execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == USER_API_KEY

    def test_application_api_key_passes(self):
        iam_client = mock.MagicMock()
        iam_client.users_loaded = True
        iam_client.api_keys_loaded = True
        iam_client.account_root_user_id = ROOT_USER_ID
        iam_client.api_keys = [
            make_api_key(
                access_key=APP_API_KEY, user_id=None, application_id=APPLICATION_ID
            )
        ]
        iam_client.organization_id = ORGANIZATION_ID

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_scaleway_provider(),
            ),
            mock.patch(
                "prowler.providers.scaleway.services.iam.iam_no_root_api_keys.iam_no_root_api_keys.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.scaleway.services.iam.iam_no_root_api_keys.iam_no_root_api_keys import (
                iam_no_root_api_keys,
            )

            result = iam_no_root_api_keys().execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_users_load_failure_returns_manual(self):
        iam_client = mock.MagicMock()
        iam_client.users_loaded = False
        iam_client.api_keys_loaded = True
        iam_client.account_root_user_id = None
        iam_client.api_keys = [
            make_api_key(access_key=ROOT_API_KEY, user_id=ROOT_USER_ID)
        ]
        iam_client.organization_id = ORGANIZATION_ID

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_scaleway_provider(),
            ),
            mock.patch(
                "prowler.providers.scaleway.services.iam.iam_no_root_api_keys.iam_no_root_api_keys.iam_client",
                new=iam_client,
            ),
        ):
            from prowler.providers.scaleway.services.iam.iam_no_root_api_keys.iam_no_root_api_keys import (
                iam_no_root_api_keys,
            )

            result = iam_no_root_api_keys().execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "Could not retrieve" in result[0].status_extended
