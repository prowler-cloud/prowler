from unittest import mock
from uuid import uuid4

from prowler.providers.stackit.services.iaas.iaas_service import Server
from tests.providers.stackit.stackit_fixtures import (
    STACKIT_PROJECT_ID,
    set_mocked_stackit_provider,
)


class Test_iaas_server_public_ip_attached:
    def _run_check(self, iaas_client):
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_stackit_provider(),
            ),
            mock.patch(
                "prowler.providers.stackit.services.iaas.iaas_service.IaaSService",
                new=iaas_client,
            ) as service_client,
            mock.patch(
                "prowler.providers.stackit.services.iaas.iaas_client.iaas_client",
                new=service_client,
            ),
        ):
            from prowler.providers.stackit.services.iaas.iaas_server_public_ip_attached.iaas_server_public_ip_attached import (
                iaas_server_public_ip_attached,
            )

            check = iaas_server_public_ip_attached()
            return check.execute()

    def test_no_servers(self):
        iaas_client = mock.MagicMock
        iaas_client.servers = []

        result = self._run_check(iaas_client)
        assert len(result) == 0

    def test_server_without_public_ip(self):
        iaas_client = mock.MagicMock
        server_id = str(uuid4())
        server_name = "private-server"

        iaas_client.servers = [
            Server(
                id=server_id,
                name=server_name,
                project_id=STACKIT_PROJECT_ID,
                region="eu01",
                has_public_ip=False,
            )
        ]

        result = self._run_check(iaas_client)
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].status_extended == f"Server {server_name} does not have a public IP address attached."
        assert result[0].resource_id == server_id
        assert result[0].resource_name == server_name
        assert result[0].location == "eu01"

    def test_server_with_public_ip(self):
        iaas_client = mock.MagicMock
        server_id = str(uuid4())
        server_name = "public-server"

        iaas_client.servers = [
            Server(
                id=server_id,
                name=server_name,
                project_id=STACKIT_PROJECT_ID,
                region="eu01",
                has_public_ip=True,
            )
        ]

        result = self._run_check(iaas_client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "has a public IP address directly attached" in result[0].status_extended
        assert result[0].resource_id == server_id
        assert result[0].resource_name == server_name
        assert result[0].location == "eu01"

    def test_multiple_servers_mixed(self):
        iaas_client = mock.MagicMock
        private_id = str(uuid4())
        public_id = str(uuid4())

        iaas_client.servers = [
            Server(
                id=private_id,
                name="private-server",
                project_id=STACKIT_PROJECT_ID,
                region="eu01",
                has_public_ip=False,
            ),
            Server(
                id=public_id,
                name="public-server",
                project_id=STACKIT_PROJECT_ID,
                region="eu01",
                has_public_ip=True,
            ),
        ]

        result = self._run_check(iaas_client)
        assert len(result) == 2

        by_id = {r.resource_id: r for r in result}
        assert by_id[private_id].status == "PASS"
        assert by_id[public_id].status == "FAIL"
