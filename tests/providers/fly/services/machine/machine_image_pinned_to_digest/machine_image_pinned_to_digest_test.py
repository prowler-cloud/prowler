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
DIGEST = "sha256:" + "a" * 64
DIGEST_IMAGE = f"registry.fly.io/test-app@{DIGEST}"
TAG_IMAGE = "registry.fly.io/test-app:latest"


def _machine(image: str, image_digest: str = "") -> FlyMachine:
    return FlyMachine(
        id=MACHINE_ID,
        name=MACHINE_NAME,
        app_name=APP_NAME,
        org_slug=ORG_SLUG,
        region=REGION,
        state="started",
        image=image,
        image_digest=image_digest,
    )


def _run(machine_client):
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

        return machine_image_pinned_to_digest().execute()


class Test_machine_image_pinned_to_digest:
    def test_no_machines(self):
        machine_client = mock.MagicMock
        machine_client.machines = {}

        assert len(_run(machine_client)) == 0

    def test_digest_pinned_image(self):
        machine_client = mock.MagicMock
        machine_client.machines = {MACHINE_ID: _machine(DIGEST_IMAGE, DIGEST)}

        result = _run(machine_client)
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].status_extended == (
            f"Machine {MACHINE_NAME} in app {APP_NAME} runs the digest-pinned "
            f"image {DIGEST_IMAGE}."
        )
        assert result[0].resource_id == MACHINE_ID
        assert result[0].region == REGION

    def test_tag_and_digest_reference_is_pinned(self):
        machine_client = mock.MagicMock
        machine_client.machines = {
            MACHINE_ID: _machine(f"registry.fly.io/test-app:v1@{DIGEST}", DIGEST)
        }

        result = _run(machine_client)
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_mutable_tag_image(self):
        machine_client = mock.MagicMock
        machine_client.machines = {MACHINE_ID: _machine(TAG_IMAGE)}

        result = _run(machine_client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended == (
            f"Machine {MACHINE_NAME} in app {APP_NAME} runs the mutable image "
            f"reference {TAG_IMAGE}, which cannot be tied to an immutable build "
            f"artifact."
        )

    def test_mutable_tag_with_resolved_digest_still_fails(self):
        # image_ref.digest is the digest Fly.io pulled for the tag; it is not a pin.
        machine_client = mock.MagicMock
        machine_client.machines = {MACHINE_ID: _machine(TAG_IMAGE, DIGEST)}

        result = _run(machine_client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended == (
            f"Machine {MACHINE_NAME} in app {APP_NAME} runs the mutable image "
            f"reference {TAG_IMAGE}, which cannot be tied to an immutable build "
            f"artifact. Fly.io reports the running image digest {DIGEST}, which "
            f"can be used to pin the image."
        )

    def test_bare_repository_reference_fails(self):
        machine_client = mock.MagicMock
        machine_client.machines = {
            MACHINE_ID: _machine("flyio/fastify-functions", DIGEST)
        }

        result = _run(machine_client)
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_missing_image_reference_is_manual(self):
        machine_client = mock.MagicMock
        machine_client.machines = {MACHINE_ID: _machine("")}

        result = _run(machine_client)
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            f"Machine {MACHINE_NAME} in app {APP_NAME} has no image reference in "
            f"its configuration, so image pinning could not be determined; verify "
            f"it manually with 'fly machine status {MACHINE_ID} -a {APP_NAME}'."
        )

    def test_missing_image_reference_with_resolved_digest_is_manual(self):
        machine_client = mock.MagicMock
        machine_client.machines = {MACHINE_ID: _machine("", DIGEST)}

        result = _run(machine_client)
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended.endswith(
            f"Fly.io reports the running image digest {DIGEST}, which can be used "
            f"to pin the image."
        )
