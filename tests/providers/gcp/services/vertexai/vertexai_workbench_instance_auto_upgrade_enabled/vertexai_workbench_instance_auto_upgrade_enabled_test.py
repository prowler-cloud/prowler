from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider

_ZONE = "us-central1-a"
_UPGRADE_SCHEDULE = "00 19 * * MON"
_CHECK_PATH = (
    "prowler.providers.gcp.services.vertexai."
    "vertexai_workbench_instance_auto_upgrade_enabled."
    "vertexai_workbench_instance_auto_upgrade_enabled"
)
_CLIENT_PATH = f"{_CHECK_PATH}.vertexai_client"


def _instance_id(name: str) -> str:
    return f"projects/{GCP_PROJECT_ID}/locations/{_ZONE}/instances/{name}"


def _mock_vertexai_client(instances=None):
    vertexai_client = mock.MagicMock()
    vertexai_client.workbench_instances = instances or []
    return vertexai_client


def _run_check(vertexai_client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ),
        mock.patch(_CLIENT_PATH, new=vertexai_client),
    ):
        from prowler.providers.gcp.services.vertexai.vertexai_workbench_instance_auto_upgrade_enabled.vertexai_workbench_instance_auto_upgrade_enabled import (
            vertexai_workbench_instance_auto_upgrade_enabled,
        )

        return vertexai_workbench_instance_auto_upgrade_enabled().execute()


def _workbench_instance(name, upgrade_schedule=None, state="ACTIVE"):
    from prowler.providers.gcp.services.vertexai.vertexai_service import (
        WorkbenchInstance,
    )

    return WorkbenchInstance(
        id=_instance_id(name),
        name=name,
        project_id=GCP_PROJECT_ID,
        location=_ZONE,
        state=state,
        upgrade_schedule=upgrade_schedule,
    )


class Test_vertexai_workbench_instance_auto_upgrade_enabled:
    def test_no_resources(self):
        result = _run_check(_mock_vertexai_client())

        assert len(result) == 0

    def test_instance_auto_upgrade_enabled(self):
        result = _run_check(
            _mock_vertexai_client(
                instances=[
                    _workbench_instance(
                        "patched-nb", upgrade_schedule=_UPGRADE_SCHEDULE
                    )
                ]
            )
        )

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Vertex AI Workbench instance patched-nb has automatic upgrades scheduled ({_UPGRADE_SCHEDULE})."
        )
        assert result[0].resource_id == _instance_id("patched-nb")
        assert result[0].resource_name == "patched-nb"
        assert result[0].project_id == GCP_PROJECT_ID
        assert result[0].location == _ZONE

    def test_instance_auto_upgrade_disabled(self):
        result = _run_check(
            _mock_vertexai_client(instances=[_workbench_instance("stale-nb")])
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Vertex AI Workbench instance stale-nb does not have automatic upgrades scheduled."
        )
        assert result[0].resource_id == _instance_id("stale-nb")

    def test_deleted_instance_is_skipped(self):
        result = _run_check(
            _mock_vertexai_client(
                instances=[_workbench_instance("gone-nb", state="DELETED")]
            )
        )

        assert len(result) == 0
