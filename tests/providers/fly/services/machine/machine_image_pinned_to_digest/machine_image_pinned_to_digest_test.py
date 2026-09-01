from unittest import mock

from prowler.providers.fly.services.machine.machine_service import FlyMachine
from tests.providers.fly.fly_fixtures import (
    APP_NAME,
    MACHINE_ID,
    MACHINE_NAME,
    ORG_SLUG,
    REGION,
    set_mocked_fly_provider,
)

CHECK_MODULE = (
    "prowler.providers.fly.services.machine.machine_image_pinned_to_digest."
    "machine_image_pinned_to_digest.machine_client"
)
DIGEST_IMAGE = "registry.fly.io/test-app@sha256:" + "a" * 64
TAG_IMAGE = "registry.fly.io/test-app:latest"


def _machine(image: str) -> FlyMachine:
    return FlyMachine(
        id=MACHINE_ID,
        name=MACHINE_NAME,
        app_name=APP_NAME,
        org_slug=ORG_SLUG,
        region=REGION,
        state="started",
        image=image,
    )


class Test_machine_image_pinned_to_digest:
    def test_no_machines(self):
        machine_client = mock.MagicMock
        machine_client.machines = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_fly_provider(),
            ),
            mock.patch(CHECK_MODULE, new=machine_client),
        ):
            from prowler.providers.fly.services.machine.machine_image_pinned_to_digest.machine_image_pinned_to_digest import (
                machine_image_pinned_to_digest,
            )

            check = machine_image_pinned_to_digest()
            result = check.execute()
            assert len(result) == 0

    def test_digest_pinned_image(self):
        machine_client = mock.MagicMock
        machine_client.machines = {MACHINE_ID: _machine(DIGEST_IMAGE)}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_fly_provider(),
            ),
            mock.patch(CHECK_MODULE, new=machine_client),
        ):
            from prowler.providers.fly.services.machine.machine_image_pinned_to_digest.machine_image_pinned_to_digest import (
                machine_image_pinned_to_digest,
            )

            check = machine_image_pinned_to_digest()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"Machine {MACHINE_NAME} in app {APP_NAME} runs the digest-pinned "
                f"image {DIGEST_IMAGE}."
            )
            assert result[0].resource_id == MACHINE_ID
            assert result[0].region == REGION

    def test_mutable_tag_image(self):
        machine_client = mock.MagicMock
        machine_client.machines = {MACHINE_ID: _machine(TAG_IMAGE)}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_fly_provider(),
            ),
            mock.patch(CHECK_MODULE, new=machine_client),
        ):
            from prowler.providers.fly.services.machine.machine_image_pinned_to_digest.machine_image_pinned_to_digest import (
                machine_image_pinned_to_digest,
            )

            check = machine_image_pinned_to_digest()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"Machine {MACHINE_NAME} in app {APP_NAME} runs the mutable image "
                f"reference {TAG_IMAGE}, which cannot be tied to an immutable build "
                f"artifact."
            )
