from unittest.mock import MagicMock, patch

import pytest

from prowler.providers.stackit.exceptions.exceptions import StackITInvalidTokenError
from prowler.providers.stackit.services.ske.ske_service import Cluster, SKEService
from tests.providers.stackit.stackit_fixtures import (
    STACKIT_PROJECT_ID,
    set_mocked_stackit_provider,
)


def mock_ske_fetch_all_regions(_):
    """Mock the _fetch_all_regions method to avoid real API calls."""


@patch(
    "prowler.providers.stackit.services.ske.ske_service.SKEService._fetch_all_regions",
    new=mock_ske_fetch_all_regions,
)
class Test_SKE_Service:
    def test_service_initialization(self):
        """Test that the SKE service initializes correctly."""
        ske_service = SKEService(set_mocked_stackit_provider())

        assert ske_service.project_id == STACKIT_PROJECT_ID
        assert ske_service.service_account_key_path is not None
        assert isinstance(ske_service.clusters, list)

    def test_service_service_account_key_path(self):
        """Test that the service correctly extracts the SA key path from provider."""
        custom_path = "/tmp/custom-sa.json"
        provider = set_mocked_stackit_provider(service_account_key_path=custom_path)
        ske_service = SKEService(provider)
        assert ske_service.service_account_key_path == custom_path

    def test_service_requests_ske_regional_clients(self):
        """Test that the service asks the provider for SKE regional clients."""
        provider = set_mocked_stackit_provider()
        SKEService(provider)
        provider.generate_regional_clients.assert_called_once_with("ske")


class Test_SKE_Service_ExtractItems:
    """Tests for the _extract_items response normalization helper."""

    def test_dict_response(self):
        assert SKEService._extract_items({"items": [1, 2]}, "list_clusters") == [1, 2]

    def test_dict_response_without_items_key(self):
        assert SKEService._extract_items({}, "list_clusters") == []

    def test_list_response(self):
        assert SKEService._extract_items(["cluster"], "list_clusters") == ["cluster"]

    def test_model_with_items_attribute(self):
        response = MagicMock(spec=["items"])
        response.items = ["cluster"]
        assert SKEService._extract_items(response, "list_clusters") == ["cluster"]

    def test_model_with_callable_items_is_rejected(self):
        # A bare MagicMock exposes ``items`` as a callable, which must not be
        # mistaken for the items list.
        assert SKEService._extract_items(MagicMock(), "list_clusters") == []

    def test_unexpected_response_type(self):
        assert SKEService._extract_items(object(), "list_clusters") == []


class Test_SKE_Service_GetField:
    """Tests for the _get_field dict/model accessor."""

    def test_none_item_returns_default(self):
        assert SKEService._get_field(None, "enabled", default="fallback") == "fallback"

    def test_dict_alias_key_is_matched(self):
        item = {"allowedCidrs": ["10.0.0.0/8"]}
        assert SKEService._get_field(item, "allowed_cidrs", "allowedCidrs") == [
            "10.0.0.0/8"
        ]

    def test_dict_missing_keys_returns_default(self):
        assert SKEService._get_field({}, "enabled", default=[]) == []

    def test_dict_false_value_is_returned_not_treated_as_missing(self):
        assert (
            SKEService._get_field({"enabled": False}, "enabled", default=True) is False
        )

    def test_model_attribute_is_read(self):
        item = MagicMock(spec=["enabled"])
        item.enabled = True
        assert SKEService._get_field(item, "enabled") is True

    def test_model_false_attribute_is_returned(self):
        item = MagicMock(spec=["enabled"])
        item.enabled = False
        assert SKEService._get_field(item, "enabled", default=True) is False

    def test_model_missing_attribute_returns_default(self):
        item = MagicMock(spec=["other"])
        assert SKEService._get_field(item, "enabled", default="fallback") == "fallback"


class Test_SKE_Service_ParseAccessScope:
    """Tests for _parse_access_scope."""

    def test_missing_network_returns_none(self):
        assert SKEService._parse_access_scope({}) is None

    def test_missing_control_plane_returns_none(self):
        assert SKEService._parse_access_scope({"network": {"id": "net"}}) is None

    def test_missing_access_scope_returns_none(self):
        assert SKEService._parse_access_scope({"network": {"controlPlane": {}}}) is None

    def test_camel_case_dict_scope(self):
        cluster_data = {"network": {"controlPlane": {"accessScope": "SNA"}}}
        assert SKEService._parse_access_scope(cluster_data) == "SNA"

    def test_snake_case_dict_scope(self):
        cluster_data = {"network": {"control_plane": {"access_scope": "PUBLIC"}}}
        assert SKEService._parse_access_scope(cluster_data) == "PUBLIC"

    def test_sdk_enum_is_normalized_to_wire_value(self):
        # ``AccessScope`` is a ``str`` Enum whose ``str()`` renders as
        # "AccessScope.SNA"; the parser must yield the "SNA" wire value.
        from stackit.ske.models.access_scope import AccessScope

        cluster_data = {"network": {"controlPlane": {"accessScope": AccessScope.SNA}}}
        assert SKEService._parse_access_scope(cluster_data) == "SNA"


class Test_SKE_Service_ParseAcl:
    """Tests for _parse_acl."""

    def test_missing_extensions_reports_no_acl(self):
        assert SKEService._parse_acl({}) == (False, [])

    def test_extensions_without_acl_reports_no_acl(self):
        assert SKEService._parse_acl({"extensions": {"dns": {}}}) == (False, [])

    def test_disabled_acl_keeps_its_cidrs(self):
        cluster_data = {
            "extensions": {"acl": {"enabled": False, "allowedCidrs": ["10.0.0.0/8"]}}
        }
        assert SKEService._parse_acl(cluster_data) == (False, ["10.0.0.0/8"])

    def test_enabled_acl_camel_case_cidrs(self):
        cluster_data = {
            "extensions": {"acl": {"enabled": True, "allowedCidrs": ["10.0.0.0/8"]}}
        }
        assert SKEService._parse_acl(cluster_data) == (True, ["10.0.0.0/8"])

    def test_enabled_acl_snake_case_cidrs(self):
        cluster_data = {
            "extensions": {"acl": {"enabled": True, "allowed_cidrs": ["10.0.0.0/8"]}}
        }
        assert SKEService._parse_acl(cluster_data) == (True, ["10.0.0.0/8"])

    def test_enabled_acl_without_cidrs(self):
        cluster_data = {"extensions": {"acl": {"enabled": True}}}
        assert SKEService._parse_acl(cluster_data) == (True, [])


class Test_SKE_Service_HandleApiCall:
    """Tests for the centralized _handle_api_call wrapper."""

    def _service(self):
        service = object.__new__(SKEService)
        service.provider = MagicMock()
        return service

    def test_returns_api_response(self):
        service = self._service()
        api_function = MagicMock(return_value={"items": []})

        assert service._handle_api_call(api_function, project_id="p") == {"items": []}
        api_function.assert_called_once_with(project_id="p")

    def test_delegates_errors_to_provider_and_reraises(self):
        service = self._service()
        error = ValueError("boom")
        api_function = MagicMock(side_effect=error)

        with pytest.raises(ValueError):
            service._handle_api_call(api_function)

        service.provider.handle_api_error.assert_called_once_with(error)


class Test_SKE_Service_ListClusters:
    """Tests for _list_clusters."""

    def _service(self):
        service = object.__new__(SKEService)
        service.provider = MagicMock()
        service.project_id = STACKIT_PROJECT_ID
        service.clusters = []
        return service

    def test_list_clusters_without_client_is_noop(self):
        """A missing regional client is logged and skipped, not fatal."""
        service = self._service()

        service._list_clusters(None, "eu01")

        assert service.clusters == []

    def test_list_clusters_populates_clusters(self):
        service = self._service()
        client = MagicMock()
        client.list_clusters.return_value = {
            "items": [
                {"name": "open-cluster"},
                {
                    "name": "locked-cluster",
                    "extensions": {
                        "acl": {"enabled": True, "allowedCidrs": ["10.0.0.0/8"]}
                    },
                    "network": {"controlPlane": {"accessScope": "PUBLIC"}},
                },
            ]
        }

        service._list_clusters(client, "eu01")

        assert [cluster.name for cluster in service.clusters] == [
            "open-cluster",
            "locked-cluster",
        ]
        # SKE has no separate cluster id; the name doubles as the identifier.
        assert service.clusters[0].id == "open-cluster"
        assert service.clusters[0].acl_enabled is False
        assert service.clusters[0].access_scope is None
        assert service.clusters[1].acl_enabled is True
        assert service.clusters[1].allowed_cidrs == ["10.0.0.0/8"]
        assert service.clusters[1].access_scope == "PUBLIC"
        assert all(
            cluster.project_id == STACKIT_PROJECT_ID and cluster.region == "eu01"
            for cluster in service.clusters
        )

    def test_cluster_processing_error_is_skipped(self):
        """A cluster that raises while being read is skipped, not fatal."""

        class MalformedCluster:
            @property
            def name(self):
                raise ValueError("malformed cluster")

        service = self._service()
        client = MagicMock()
        client.list_clusters.return_value = {"items": [MalformedCluster()]}

        service._list_clusters(client, "eu01")

        assert service.clusters == []


class Test_SKE_Service_FetchAllRegions:
    """Tests for the region fetch loop and its error semantics."""

    class _NotFound(Exception):
        status = 404

    class _Unauthorized(Exception):
        status = 401

    class _ServerError(Exception):
        status = 500

    def _service(self, regional_clients):
        from prowler.providers.stackit.stackit_provider import StackitProvider

        service = object.__new__(SKEService)
        service.provider = MagicMock()
        # Reuse the real centralized error handler so 401/403/404 semantics
        # match production.
        service.provider.handle_api_error = StackitProvider.handle_api_error
        service.project_id = STACKIT_PROJECT_ID
        service.regional_clients = regional_clients
        service.clusters = []
        return service

    def _good_client(self, cluster_name="cluster-eu01"):
        client = MagicMock()
        client.list_clusters.return_value = {"items": [{"name": cluster_name}]}
        return client

    def _failing_client(self, error):
        client = MagicMock()
        client.list_clusters.side_effect = error
        return client

    def test_skips_region_where_project_is_absent(self):
        service = self._service(
            {
                "eu01": self._good_client(),
                "eu02": self._failing_client(self._NotFound()),
            }
        )

        service._fetch_all_regions()

        # eu01 cluster is collected; the eu02 404 is skipped silently.
        assert [cluster.name for cluster in service.clusters] == ["cluster-eu01"]

    def test_invalid_token_aborts_the_scan(self):
        service = self._service({"eu01": self._failing_client(self._Unauthorized())})

        with pytest.raises(StackITInvalidTokenError):
            service._fetch_all_regions()

    def test_unexpected_error_propagates(self):
        service = self._service({"eu01": self._failing_client(self._ServerError())})

        with pytest.raises(self._ServerError):
            service._fetch_all_regions()


class Test_SKE_Service_SdkModelShapes:
    """Regression coverage for object-shaped (SDK model) API responses.

    ``_extract_items`` accepts both raw dicts and SDK models, so the cluster
    parsing has to read either shape. Reading only dict keys would silently drop
    the ACL of an SDK-model cluster and report a restricted cluster as exposed,
    or worse, miss the ACL of an exposed one.
    """

    @staticmethod
    def _sdk_cluster(name, acl=None, access_scope=None):
        """Build a real ``stackit.ske`` Cluster model with optional ACL and scope."""
        from stackit.ske.models.cluster import Cluster as SDKCluster
        from stackit.ske.models.extension import Extension
        from stackit.ske.models.image import Image
        from stackit.ske.models.kubernetes import Kubernetes
        from stackit.ske.models.machine import Machine
        from stackit.ske.models.network import Network
        from stackit.ske.models.nodepool import Nodepool
        from stackit.ske.models.v2_control_plane_network import V2ControlPlaneNetwork
        from stackit.ske.models.volume import Volume

        nodepool = Nodepool(
            name="np",
            availabilityZones=["eu01-1"],
            maximum=1,
            minimum=1,
            machine=Machine(image=Image(name="flatcar", version="1.0"), type="g1.2"),
            volume=Volume(size=20),
        )
        return SDKCluster(
            name=name,
            kubernetes=Kubernetes(version="1.31.0"),
            nodepools=[nodepool],
            extensions=Extension(acl=acl) if acl is not None else None,
            network=(
                Network(controlPlane=V2ControlPlaneNetwork(accessScope=access_scope))
                if access_scope is not None
                else None
            ),
        )

    @staticmethod
    def _sdk_acl(allowed_cidrs, enabled=True):
        """Build a real ``stackit.ske`` ACL extension model."""
        from stackit.ske.models.acl import ACL

        return ACL(allowedCidrs=allowed_cidrs, enabled=enabled)

    def test_sdk_model_acl_is_parsed(self):
        cluster = self._sdk_cluster("locked-clst", acl=self._sdk_acl(["10.0.0.0/8"]))

        assert SKEService._parse_acl(cluster) == (True, ["10.0.0.0/8"])

    def test_sdk_model_without_extensions_reports_no_acl(self):
        cluster = self._sdk_cluster("open-clst")

        assert SKEService._parse_acl(cluster) == (False, [])
        assert SKEService._parse_access_scope(cluster) is None

    def test_sdk_model_access_scope_enum_is_normalized(self):
        cluster = self._sdk_cluster("sna-clst", access_scope="SNA")

        assert SKEService._parse_access_scope(cluster) == "SNA"

    def test_list_clusters_with_sdk_response_and_model_items(self):
        from stackit.ske.models.list_clusters_response import ListClustersResponse

        service = object.__new__(SKEService)
        service.provider = MagicMock()
        service.project_id = STACKIT_PROJECT_ID
        service.clusters = []

        client = MagicMock()
        client.list_clusters.return_value = ListClustersResponse(
            items=[
                self._sdk_cluster("open-clst"),
                self._sdk_cluster("locked-clst", acl=self._sdk_acl(["10.0.0.0/8"])),
            ]
        )

        service._list_clusters(client, "eu01")

        assert [cluster.name for cluster in service.clusters] == [
            "open-clst",
            "locked-clst",
        ]
        # An object-shaped ACL must not be dropped: the restricted cluster is
        # not reported as internet-exposed, and the open one still is.
        assert service.clusters[0].has_public_endpoint() is True
        assert service.clusters[1].acl_enabled is True
        assert service.clusters[1].allowed_cidrs == ["10.0.0.0/8"]
        assert service.clusters[1].has_public_endpoint() is False

    def test_dict_and_sdk_model_shapes_parse_identically(self):
        """The same cluster expressed as a dict or an SDK model must agree."""
        sdk_cluster = self._sdk_cluster(
            "locked-clst",
            acl=self._sdk_acl(["10.0.0.0/8"]),
            access_scope="PUBLIC",
        )
        dict_cluster = {
            "name": "locked-clst",
            "extensions": {"acl": {"enabled": True, "allowedCidrs": ["10.0.0.0/8"]}},
            "network": {"controlPlane": {"accessScope": "PUBLIC"}},
        }

        assert SKEService._parse_acl(sdk_cluster) == SKEService._parse_acl(dict_cluster)
        assert SKEService._parse_access_scope(
            sdk_cluster
        ) == SKEService._parse_access_scope(dict_cluster)


class Test_SKE_Cluster_Model:
    """Tests for the Cluster public-endpoint logic."""

    def _cluster(self, **kwargs):
        defaults = {
            "id": "test-cluster",
            "name": "test-cluster",
            "project_id": STACKIT_PROJECT_ID,
            "region": "eu01",
        }
        defaults.update(kwargs)
        return Cluster(**defaults)

    def test_private_control_plane_passes_regardless_of_acl(self):
        cluster = self._cluster(access_scope="SNA", acl_enabled=False)

        assert cluster.has_private_control_plane() is True
        assert cluster.has_public_endpoint() is False

    def test_disabled_acl_is_publicly_reachable(self):
        cluster = self._cluster(acl_enabled=False)

        assert cluster.has_private_control_plane() is False
        assert cluster.has_public_endpoint() is True

    def test_public_scope_with_restricted_acl_is_not_publicly_reachable(self):
        cluster = self._cluster(
            access_scope="PUBLIC", acl_enabled=True, allowed_cidrs=["10.0.0.0/8"]
        )

        assert cluster.unrestricted_cidrs() == []
        assert cluster.has_public_endpoint() is False

    @pytest.mark.parametrize("unrestricted_cidr", ["0.0.0.0/0", "::/0"])
    def test_unrestricted_cidr_in_allowlist_is_publicly_reachable(
        self, unrestricted_cidr
    ):
        cluster = self._cluster(
            acl_enabled=True, allowed_cidrs=["10.0.0.0/8", unrestricted_cidr]
        )

        assert cluster.unrestricted_cidrs() == [unrestricted_cidr]
        assert cluster.has_public_endpoint() is True

    def test_enabled_acl_with_empty_allowlist_is_not_publicly_reachable(self):
        cluster = self._cluster(acl_enabled=True, allowed_cidrs=[])

        assert cluster.has_public_endpoint() is False

    def test_unset_access_scope_falls_back_to_the_acl(self):
        assert (
            self._cluster(
                access_scope=None, acl_enabled=True, allowed_cidrs=["10.0.0.0/8"]
            ).has_public_endpoint()
            is False
        )
        assert (
            self._cluster(access_scope=None, acl_enabled=False).has_public_endpoint()
            is True
        )
