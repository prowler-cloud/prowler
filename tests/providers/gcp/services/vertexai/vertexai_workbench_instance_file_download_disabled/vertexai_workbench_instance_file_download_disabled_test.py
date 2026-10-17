from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider

_ZONE = "us-central1-a"
_CHECK_PATH = (
    "prowler.providers.gcp.services.vertexai."
    "vertexai_workbench_instance_file_download_disabled."
    "vertexai_workbench_instance_file_download_disabled"
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
        from prowler.providers.gcp.services.vertexai.vertexai_workbench_instance_file_download_disabled.vertexai_workbench_instance_file_download_disabled import (
            vertexai_workbench_instance_file_download_disabled,
        )

        return vertexai_workbench_instance_file_download_disabled().execute()


def _workbench_instance(name, file_download_disabled, state="ACTIVE"):
    from prowler.providers.gcp.services.vertexai.vertexai_service import (
        WorkbenchInstance,
    )

    return WorkbenchInstance(
        id=_instance_id(name),
        name=name,
        project_id=GCP_PROJECT_ID,
        location=_ZONE,
        state=state,
        file_download_disabled=file_download_disabled,
    )


class Test_vertexai_workbench_instance_file_download_disabled:
    def test_no_resources(self):
        result = _run_check(_mock_vertexai_client())

        assert len(result) == 0

    def test_instance_file_download_disabled(self):
        result = _run_check(
            _mock_vertexai_client(
                instances=[
                    _workbench_instance("locked-nb", file_download_disabled=True)
                ]
            )
        )

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "Vertex AI Workbench instance locked-nb has file downloads disabled."
        )
        assert result[0].resource_id == _instance_id("locked-nb")
        assert result[0].resource_name == "locked-nb"
        assert result[0].project_id == GCP_PROJECT_ID
        assert result[0].location == _ZONE

    def test_instance_file_download_enabled(self):
        result = _run_check(
            _mock_vertexai_client(
                instances=[_workbench_instance("open-nb", file_download_disabled=False)]
            )
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Vertex AI Workbench instance open-nb has file downloads enabled."
        )
        assert result[0].resource_id == _instance_id("open-nb")

    def test_deleted_instance_is_skipped(self):
        result = _run_check(
            _mock_vertexai_client(
                instances=[
                    _workbench_instance(
                        "gone-nb", file_download_disabled=False, state="DELETED"
                    )
                ]
            )
        )

        assert len(result) == 0
