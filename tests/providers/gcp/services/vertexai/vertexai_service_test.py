from unittest.mock import MagicMock, patch

from prowler.providers.gcp.services.vertexai.vertexai_service import VertexAI
from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_is_api_active,
    set_mocked_gcp_provider,
)

_ZONE = "us-central1-a"
_INSTANCE_NAME = "my-workbench"
_INSTANCE_ID = f"projects/{GCP_PROJECT_ID}/locations/{_ZONE}/instances/{_INSTANCE_NAME}"
_NETWORK = f"projects/{GCP_PROJECT_ID}/global/networks/default"


def _make_notebooks_client(instances_list=None, list_error=None):
    """Return a mock Notebooks v2 API client for Workbench instances."""
    client = MagicMock()
    instances = client.projects().locations().instances()
    if list_error:
        instances.list().execute.side_effect = list_error
    else:
        instances.list().execute.return_value = {"instances": instances_list or []}
    instances.list_next.return_value = None
    return client


def _build_service(client):
    with (
        patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
            new=mock_is_api_active,
        ),
        patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
            new=lambda *_: client,
        ),
    ):
        return VertexAI(set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID]))


class TestVertexAIService:
    def test_service_uses_notebooks_v2_api(self):
        vertexai_client = _build_service(_make_notebooks_client())

        assert vertexai_client.service == "notebooks"
        assert vertexai_client.api_version == "v2"
        assert vertexai_client.project_ids == [GCP_PROJECT_ID]
        assert vertexai_client.workbench_instances == []

    def test_lists_instances_across_all_locations(self):
        client = _make_notebooks_client()
        _build_service(client)

        client.projects().locations().instances().list.assert_called_with(
            parent=f"projects/{GCP_PROJECT_ID}/locations/-"
        )

    def test_get_workbench_instance_hardened(self):
        vertexai_client = _build_service(
            _make_notebooks_client(
                instances_list=[
                    {
                        "name": _INSTANCE_ID,
                        "state": "ACTIVE",
                        "gceSetup": {
                            "disablePublicIp": True,
                            "metadata": {"notebook-disable-root": "true"},
                            "networkInterfaces": [{"network": _NETWORK}],
                        },
                    }
                ]
            )
        )

        assert len(vertexai_client.workbench_instances) == 1
        instance = vertexai_client.workbench_instances[0]
        assert instance.id == _INSTANCE_ID
        assert instance.name == _INSTANCE_NAME
        assert instance.project_id == GCP_PROJECT_ID
        assert instance.location == _ZONE
        assert instance.state == "ACTIVE"
        assert instance.public_ip_disabled is True
        assert instance.root_access_disabled is True
        assert instance.network == _NETWORK

    def test_get_workbench_instance_defaults(self):
        vertexai_client = _build_service(
            _make_notebooks_client(
                instances_list=[{"name": _INSTANCE_ID, "gceSetup": {}}]
            )
        )

        instance = vertexai_client.workbench_instances[0]
        assert instance.state == "STATE_UNSPECIFIED"
        assert instance.public_ip_disabled is False
        assert instance.root_access_disabled is False
        assert instance.network is None

    def test_root_access_metadata_is_case_insensitive(self):
        vertexai_client = _build_service(
            _make_notebooks_client(
                instances_list=[
                    {
                        "name": _INSTANCE_ID,
                        "gceSetup": {"metadata": {"notebook-disable-root": "TRUE"}},
                    }
                ]
            )
        )

        assert vertexai_client.workbench_instances[0].root_access_disabled is True

    def test_root_access_metadata_false(self):
        vertexai_client = _build_service(
            _make_notebooks_client(
                instances_list=[
                    {
                        "name": _INSTANCE_ID,
                        "gceSetup": {"metadata": {"notebook-disable-root": "false"}},
                    }
                ]
            )
        )

        assert vertexai_client.workbench_instances[0].root_access_disabled is False

    def test_unreachable_locations_return_no_instances(self):
        client = _make_notebooks_client()
        client.projects().locations().instances().list().execute.return_value = {
            "unreachable": ["us-west1-a", "us-central1-b"]
        }

        vertexai_client = _build_service(client)

        assert vertexai_client.workbench_instances == []

    def test_unreachable_on_later_page_keeps_listed_instances(self):
        client = _make_notebooks_client(
            instances_list=[{"name": _INSTANCE_ID, "gceSetup": {}}]
        )
        second_page = MagicMock()
        second_page.execute.return_value = {"unreachable": ["us-west1-a"]}
        client.projects().locations().instances().list_next.side_effect = [
            second_page,
            None,
        ]

        vertexai_client = _build_service(client)

        assert [i.name for i in vertexai_client.workbench_instances] == [_INSTANCE_NAME]

    def test_list_error_returns_no_instances(self):
        vertexai_client = _build_service(
            _make_notebooks_client(list_error=Exception("permission denied"))
        )

        assert vertexai_client.workbench_instances == []
