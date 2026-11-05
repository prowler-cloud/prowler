from unittest import mock

from prowler.providers.e2enetworks.services.database.database_service import (
    DatabaseInstance,
)
from tests.providers.e2enetworks.e2enetworks_fixtures import (
    set_mocked_e2enetworks_provider,
)

CLIENT_PATH = "prowler.providers.e2enetworks.services.database.database_replica_public_ip_not_assigned.database_replica_public_ip_not_assigned.database_client"


class Test_database_replica_public_ip_not_assigned:
    def test_no_instances(self):
        client = mock.MagicMock()
        client.instances = []
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.database.database_replica_public_ip_not_assigned.database_replica_public_ip_not_assigned import (
                database_replica_public_ip_not_assigned,
            )

            assert database_replica_public_ip_not_assigned().execute() == []

    def test_database_replica_public_ip_not_assigned_compliant(self):
        client = mock.MagicMock()
        client.instances = [
            DatabaseInstance(
                id="1",
                name="ok",
                cluster_id="c1",
                cluster_name="cluster",
                location="Delhi",
                role="replica",
                has_public_ip=False,
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.database.database_replica_public_ip_not_assigned.database_replica_public_ip_not_assigned import (
                database_replica_public_ip_not_assigned,
            )

            findings = database_replica_public_ip_not_assigned().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"

    def test_database_replica_public_ip_not_assigned_non_compliant(self):
        client = mock.MagicMock()
        client.instances = [
            DatabaseInstance(
                id="2",
                name="bad",
                cluster_id="c1",
                cluster_name="cluster",
                location="Delhi",
                role="replica",
                has_public_ip=True,
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.database.database_replica_public_ip_not_assigned.database_replica_public_ip_not_assigned import (
                database_replica_public_ip_not_assigned,
            )

            findings = database_replica_public_ip_not_assigned().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
