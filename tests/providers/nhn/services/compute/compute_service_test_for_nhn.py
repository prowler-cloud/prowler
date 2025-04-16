from unittest.mock import MagicMock, patch

from prowler.providers.nhn.services.compute.compute_service import NHNComputeService
from tests.providers.nhn.nhn_fixtures import set_mocked_nhn_provider


class TestNHNComputeService:
    @patch("prowler.providers.nhn.services.compute.compute_service.logger")
    def test_compute_service_basic(self, mock_logger):
        """
        Test that NHNComputeService properly calls _list_servers(),
        _get_server_detail() for each server, and populates self.instances.
        """
        # create a mocked NHN Provider
        provider = set_mocked_nhn_provider(
            username="testUser",
            password="testPass",
            tenant_id="tenant123",
        )

        # define mocked responses
        mocked_response_servers = MagicMock()
        mocked_response_servers.status_code = 200
        mocked_response_servers.json.return_value = {
            "servers": [
                {"id": "server1", "name": "myserver1"},
                {"id": "server2", "name": "myserver2"},
            ]
        }

        mocked_response_server1 = MagicMock()
        mocked_response_server1.status_code = 200
        mocked_response_server1.json.return_value = {
            "server": {
                "addresses": {
                    "vpc1": [
                        {"OS-EXT-IPS:type": "floating"},
                    ]
                },
                "security_groups": [{"name": "default"}],
                "metadata": {"login_username": "root"},
            }
        }

        mocked_response_server2 = MagicMock()
        mocked_response_server2.status_code = 200
        mocked_response_server2.json.return_value = {
            "server": {
                "addresses": {
                    "vpc1": [
                        {"OS-EXT-IPS:type": "fixed"},
                    ]
                },
                "security_groups": [{"name": "default"}, {"name": "other-sg"}],
                "metadata": {"login_username": "regularuser"},
            }
        }

        def get_side_effect(url, timeout=10):
            print(f"Called with timeout={timeout}")
            if (
                "/v2/tenant123/servers" in url
                and not url.endswith("server1")
                and not url.endswith("server2")
            ):
                return mocked_response_servers
            elif url.endswith("server1"):
                return mocked_response_server1
            elif url.endswith("server2"):
                return mocked_response_server2
            else:
                mock_404 = MagicMock()
                mock_404.status_code = 404
                mock_404.text = "Not Found"
                return mock_404

        provider.session.get.side_effect = get_side_effect

        # create NHNComputeService, which internally calls _get_instances()
        compute_service = NHNComputeService(provider)

        assert len(compute_service.instances) == 2

        # first instance
        inst1 = compute_service.instances[0]
        assert inst1.id == "server1"
        assert inst1.name == "myserver1"
        assert inst1.public_ip is True
        assert inst1.security_groups is True
        assert inst1.login_user is True

        # second instance
        inst2 = compute_service.instances[1]
        assert inst2.id == "server2"
        assert inst2.name == "myserver2"
        assert inst2.public_ip is False
        assert inst2.security_groups is False
        assert inst2.login_user is False

        mock_logger.error.assert_not_called()
