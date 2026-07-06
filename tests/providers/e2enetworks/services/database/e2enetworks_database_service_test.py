from unittest.mock import MagicMock, patch

from prowler.providers.e2enetworks.services.database.database_service import Database


class TestDatabaseService:
    @patch(
        "prowler.providers.e2enetworks.services.database.database_service.E2eNetworksService.__init__"
    )
    def test_fetch_clusters_enriches_detail(self, mock_super_init):
        mock_super_init.return_value = None

        provider = MagicMock()
        provider.session.locations = ["Delhi"]
        service = Database.__new__(Database)
        service.provider = provider
        service.client = MagicMock()
        service.clusters = []
        service.instances = []

        service.client.get_data.side_effect = [
            [
                {
                    "id": 5276,
                    "name": "E2E-DBaaS-1",
                    "status": "RUNNING",
                    "software": {"name": "MySQL", "version": "8.0"},
                    "master_node": {
                        "instance_id": 10650,
                        "node_name": "E2E-DBaaS-1-Node-1",
                        "public_ip_address": "164.52.1.1",
                        "ssl": True,
                        "database": {"username": "dbadmin"},
                    },
                }
            ],
            {
                "id": 5276,
                "name": "E2E-DBaaS-1",
                "status": "RUNNING",
                "backup_enabled": True,
                "whitelisted_ips": ["203.0.113.0/24"],
                "master_node": {
                    "instance_id": 10650,
                    "node_name": "E2E-DBaaS-1-Node-1",
                    "public_ip_address": "164.52.1.1",
                    "ssl": True,
                    "database": {"username": "dbadmin"},
                },
                "slave_nodes": [
                    {
                        "instance_id": 10651,
                        "node_name": "E2E-DBaaS-1-Replica-1",
                        "public_ip_address": None,
                        "database": {"username": "dbadmin"},
                    }
                ],
            },
        ]

        service._fetch_clusters()

        assert len(service.clusters) == 1
        cluster = service.clusters[0]
        assert cluster.backup_enabled is True
        assert cluster.master_ssl_enabled is True
        assert cluster.master_has_public_ip is True
        assert cluster.master_username == "dbadmin"
        assert len(service.instances) == 2
        assert service.instances[1].role == "replica"
