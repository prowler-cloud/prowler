from unittest import mock

from prowler.providers.fly.exceptions.exceptions import FlyAuthenticationError
from prowler.providers.fly.services.volume.volume_service import Volume
from tests.providers.fly.fly_fixtures import (
    APP_NAME,
    ORG_SLUG,
    REGION,
    VOLUME_ID,
    VOLUME_NAME,
    set_mocked_fly_provider,
)

VOLUMES_PAYLOAD = [
    {
        "id": VOLUME_ID,
        "name": VOLUME_NAME,
        "state": "created",
        "size_gb": 10,
        "region": REGION,
        "zone": "b6a7",
        "encrypted": True,
        "attached_machine_id": "148e21eb1de389",
        "attached_alloc_id": None,
        "snapshot_retention": 5,
        "auto_backup_enabled": True,
    },
    {
        "id": "vol_unencrypted",
        "name": None,
        "state": None,
        "size_gb": 1,
        "region": None,
        "encrypted": False,
        "attached_machine_id": None,
        "snapshot_retention": None,
        "auto_backup_enabled": False,
    },
]


def _volume_service(get_side_effect) -> Volume:
    provider = set_mocked_fly_provider()
    with (
        mock.patch.object(Volume, "_app_scope", return_value=[(ORG_SLUG, APP_NAME)]),
        mock.patch.object(Volume, "_get", side_effect=get_side_effect),
    ):
        return Volume(provider)


class Test_Volume_service:
    def test_volumes_are_parsed(self):
        service = _volume_service([VOLUMES_PAYLOAD])

        volume = service.volumes[f"{APP_NAME}/{VOLUME_ID}"]
        assert volume.name == VOLUME_NAME
        assert volume.app_name == APP_NAME
        assert volume.org_slug == ORG_SLUG
        assert volume.region == REGION
        assert volume.state == "created"
        assert volume.size_gb == 10
        assert volume.encrypted is True
        assert volume.auto_backup_enabled is True
        assert volume.snapshot_retention == 5
        assert volume.attached_machine_id == "148e21eb1de389"

    def test_null_fields_get_defaults(self):
        service = _volume_service([VOLUMES_PAYLOAD])

        volume = service.volumes[f"{APP_NAME}/vol_unencrypted"]
        assert volume.name == "vol_unencrypted"
        assert volume.state == ""
        assert volume.region == "global"
        assert volume.encrypted is False
        assert volume.snapshot_retention == 0
        assert volume.attached_machine_id is None

    def test_missing_volumes_are_skipped(self):
        service = _volume_service([None])

        assert service.volumes == {}

    def test_listing_failure_is_logged(self):
        with mock.patch(
            "prowler.providers.fly.services.volume.volume_service.logger"
        ) as logger_mock:
            service = _volume_service([RuntimeError("boom")])

        assert service.volumes == {}
        logger_mock.error.assert_called_once()
        assert APP_NAME in logger_mock.error.call_args.args[0]

    def test_forbidden_app_does_not_abort_other_apps(self):
        provider = set_mocked_fly_provider()
        with (
            mock.patch.object(
                Volume,
                "_app_scope",
                return_value=[(ORG_SLUG, "denied-app"), (ORG_SLUG, APP_NAME)],
            ),
            mock.patch.object(
                Volume,
                "_get",
                side_effect=[
                    FlyAuthenticationError(message="Access denied (403)"),
                    VOLUMES_PAYLOAD,
                ],
            ),
            mock.patch(
                "prowler.providers.fly.services.volume.volume_service.logger"
            ) as logger_mock,
        ):
            service = Volume(provider)

        assert set(service.volumes) == {
            f"{APP_NAME}/{VOLUME_ID}",
            f"{APP_NAME}/vol_unencrypted",
        }
        logger_mock.error.assert_called_once()
        assert "denied-app" in logger_mock.error.call_args.args[0]
