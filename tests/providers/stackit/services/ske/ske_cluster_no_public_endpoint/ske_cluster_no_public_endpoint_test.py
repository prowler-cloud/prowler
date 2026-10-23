from unittest import mock

from prowler.providers.stackit.services.ske.ske_service import Cluster
from tests.providers.stackit.stackit_fixtures import (
    STACKIT_PROJECT_ID,
    set_mocked_stackit_provider,
)


class Test_ske_cluster_no_public_endpoint:
    def _run_check(self, ske_client):
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_stackit_provider(),
            ),
            mock.patch(
                "prowler.providers.stackit.services.ske.ske_service.SKEService",
                new=ske_client,
            ) as service_client,
            mock.patch(
                "prowler.providers.stackit.services.ske.ske_client.ske_client",
                new=service_client,
            ),
        ):
            from prowler.providers.stackit.services.ske.ske_cluster_no_public_endpoint.ske_cluster_no_public_endpoint import (
                ske_cluster_no_public_endpoint,
            )

            check = ske_cluster_no_public_endpoint()
            return check.execute()

    def _cluster(self, name="test-cluster", **kwargs):
        defaults = {
            "id": name,
            "name": name,
            "project_id": STACKIT_PROJECT_ID,
            "region": "eu01",
        }
        defaults.update(kwargs)
        return Cluster(**defaults)

    def test_no_clusters(self):
        ske_client = mock.MagicMock
        ske_client.clusters = []

        result = self._run_check(ske_client)
        assert len(result) == 0

    def test_cluster_without_acl_is_public(self):
        ske_client = mock.MagicMock
        ske_client.clusters = [self._cluster(name="open-cluster", acl_enabled=False)]

        result = self._run_check(ske_client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "SKE cluster open-cluster exposes its Kubernetes API endpoint to the "
            "internet because the ACL extension is not enabled."
        )
        assert result[0].resource_id == "open-cluster"
        assert result[0].resource_name == "open-cluster"
        assert result[0].project_id == STACKIT_PROJECT_ID
        assert result[0].location == "eu01"

    def test_cluster_with_unrestricted_ipv4_cidr_is_public(self):
        ske_client = mock.MagicMock
        ske_client.clusters = [
            self._cluster(
                name="wide-cluster",
                acl_enabled=True,
                allowed_cidrs=["10.0.0.0/8", "0.0.0.0/0"],
            )
        ]

        result = self._run_check(ske_client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "SKE cluster wide-cluster exposes its Kubernetes API endpoint to the "
            "internet because its ACL allows unrestricted access from 0.0.0.0/0."
        )

    def test_cluster_with_unrestricted_ipv6_cidr_is_public(self):
        ske_client = mock.MagicMock
        ske_client.clusters = [
            self._cluster(name="v6-cluster", acl_enabled=True, allowed_cidrs=["::/0"])
        ]

        result = self._run_check(ske_client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "unrestricted access from ::/0." in result[0].status_extended

    def test_cluster_with_restricted_acl_passes(self):
        ske_client = mock.MagicMock
        ske_client.clusters = [
            self._cluster(
                name="locked-cluster",
                access_scope="PUBLIC",
                acl_enabled=True,
                allowed_cidrs=["10.0.0.0/8", "192.0.2.0/24"],
            )
        ]

        result = self._run_check(ske_client)
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "SKE cluster locked-cluster restricts access to its Kubernetes API "
            "endpoint to 2 allowed CIDR(s)."
        )

    def test_cluster_with_private_control_plane_passes_without_acl(self):
        ske_client = mock.MagicMock
        ske_client.clusters = [
            self._cluster(name="sna-cluster", access_scope="SNA", acl_enabled=False)
        ]

        result = self._run_check(ske_client)
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "SKE cluster sna-cluster has a private control plane and its Kubernetes "
            "API endpoint is not reachable from the internet."
        )

    def test_mixed_clusters_report_independently(self):
        ske_client = mock.MagicMock
        ske_client.clusters = [
            self._cluster(name="open-cluster", acl_enabled=False),
            self._cluster(
                name="locked-cluster", acl_enabled=True, allowed_cidrs=["10.0.0.0/8"]
            ),
            self._cluster(name="sna-cluster", access_scope="SNA"),
        ]

        result = self._run_check(ske_client)
        assert len(result) == 3
        assert [report.status for report in result] == ["FAIL", "PASS", "PASS"]
        assert [report.resource_name for report in result] == [
            "open-cluster",
            "locked-cluster",
            "sna-cluster",
        ]
