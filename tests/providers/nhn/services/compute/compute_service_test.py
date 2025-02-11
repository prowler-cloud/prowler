import pytest
from unittest.mock import patch, MagicMock
from uuid import uuid4

from prowler.providers.nhn.services.compute.compute_service import NHNComputeService, Instance
from tests.providers.nhn.nhn_fixtures import set_mocked_nhn_provider


class TestNHNComputeService:
    @patch("prowler.providers.nhn.services.compute.compute_service.logger")
    def test_compute_service_basic(self, mock_logger):
        """
        Test that NHNComputeService properly calls _list_servers(),
        _get_server_detail() for each server, and populates self.instances.
        """
        # 1) 준비: Mock된 NHN Provider 생성 (세션, 토큰 등 가짜 설정)
        provider = set_mocked_nhn_provider(
            username="testUser",
            password="testPass",
            tenant_id="tenant123",
        )

        # 2) session.get 응답을 side_effect로 설정
        # 첫 호출 -> /v2/tenant123/servers
        # 두 번째 -> /v2/tenant123/servers/server1
        # 세 번째 -> /v2/tenant123/servers/server2
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
                "metadata": {
                    "login_username": "root"
                }
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
                "metadata": {
                    "login_username": "regularuser"
                }
            }
        }

        def get_side_effect(url, timeout=10):
            if "/v2/tenant123/servers" in url and not url.endswith("server1") and not url.endswith("server2"):
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

        # 3) 실행: NHNComputeService 생성 -> 내부에서 _get_instances() 호출
        compute_service = NHNComputeService(provider)

        # 4) 검증
        # 서버 2개 => instances 2개
        assert len(compute_service.instances) == 2

        # 첫 번째 인스턴스
        inst1 = compute_service.instances[0]
        assert inst1.id == "server1"
        assert inst1.name == "myserver1"
        # server1: addresses => floating => public_ip=True
        assert inst1.public_ip is True
        # security_groups => ["default"] => =>_check_security_groups => True
        # 즉 "only default" => True
        assert inst1.security_groups is True
        # login_username => "root" => =>_check_login_user => True
        assert inst1.login_user is True

        # 두 번째 인스턴스
        inst2 = compute_service.instances[1]
        assert inst2.id == "server2"
        assert inst2.name == "myserver2"
        # addresses => "fixed" => public_ip=False
        assert inst2.public_ip is False
        # security_groups => ["default","other-sg"] => =>_check_security_groups => False
        # default 말고 다른 것도 있으면 -> False
        assert inst2.security_groups is False
        # login_username => "regularuser" => =>_check_login_user => False
        assert inst2.login_user is False

        # 로그나 예외 발생 없었는지 확인 (선택)
        mock_logger.error.assert_not_called()
