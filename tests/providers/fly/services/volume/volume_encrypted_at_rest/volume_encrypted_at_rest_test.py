from unittest import mock

from prowler.providers.fly.services.volume.volume_service import FlyVolume
from tests.providers.fly.fly_fixtures import (
    APP_NAME,
    ORG_SLUG,
    REGION,
    VOLUME_ID,
    VOLUME_NAME,
    set_mocked_fly_provider,
)

CHECK_MODULE = (
    "prowler.providers.fly.services.volume.volume_encrypted_at_rest."
    "volume_encrypted_at_rest.volume_client"
)


def _volume(encrypted: bool) -> FlyVolume:
    return FlyVolume(
        id=VOLUME_ID,
        name=VOLUME_NAME,
        app_name=APP_NAME,
        org_slug=ORG_SLUG,
        region=REGION,
        state="created",
        size_gb=10,
        encrypted=encrypted,
    )


class Test_volume_encrypted_at_rest:
    def test_no_volumes(self):
        volume_client = mock.MagicMock
        volume_client.volumes = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_fly_provider(),
            ),
            mock.patch(CHECK_MODULE, new=volume_client),
        ):
            from prowler.providers.fly.services.volume.volume_encrypted_at_rest.volume_encrypted_at_rest import (
                volume_encrypted_at_rest,
            )

            check = volume_encrypted_at_rest()
            result = check.execute()
            assert len(result) == 0

    def test_encrypted_volume(self):
        volume_client = mock.MagicMock
        volume_client.volumes = {VOLUME_ID: _volume(True)}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_fly_provider(),
            ),
            mock.patch(CHECK_MODULE, new=volume_client),
        ):
            from prowler.providers.fly.services.volume.volume_encrypted_at_rest.volume_encrypted_at_rest import (
                volume_encrypted_at_rest,
            )

            check = volume_encrypted_at_rest()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"Volume {VOLUME_NAME} ({VOLUME_ID}) in app {APP_NAME} is encrypted "
                f"at rest."
            )
            assert result[0].resource_id == VOLUME_ID
            assert result[0].region == REGION

    def test_unencrypted_volume(self):
        volume_client = mock.MagicMock
        volume_client.volumes = {VOLUME_ID: _volume(False)}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_fly_provider(),
            ),
            mock.patch(CHECK_MODULE, new=volume_client),
        ):
            from prowler.providers.fly.services.volume.volume_encrypted_at_rest.volume_encrypted_at_rest import (
                volume_encrypted_at_rest,
            )

            check = volume_encrypted_at_rest()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"Volume {VOLUME_NAME} ({VOLUME_ID}) in app {APP_NAME} is not "
                f"encrypted at rest."
            )
