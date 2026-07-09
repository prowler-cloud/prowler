from unittest.mock import MagicMock, patch

from prowler.providers.e2enetworks.services.securitygroup.securitygroup_service import (
    SecurityGroups,
)


class TestSecurityGroupService:
    @patch(
        "prowler.providers.e2enetworks.services.securitygroup.securitygroup_service.E2eNetworksService.__init__"
    )
    def test_fetch_security_groups_parses_rules(self, mock_super_init):
        mock_super_init.return_value = None

        provider = MagicMock()
        provider.session.locations = ["Delhi"]
        service = SecurityGroups.__new__(SecurityGroups)
        service.provider = provider
        service.client = MagicMock()
        service.security_groups = []

        service.client.get_data.return_value = [
            {
                "id": 10,
                "name": "default",
                "description": "Default security group",
                "is_default": True,
                "is_all_traffic_rule": True,
                "rules": [
                    {
                        "id": 1,
                        "rule_type": "Inbound",
                        "protocol_name": "All",
                        "port_range": "1-65535",
                        "network": "0.0.0.0",
                        "network_cidr": "0",
                    }
                ],
            }
        ]

        service._fetch_security_groups()

        assert len(service.security_groups) == 1
        group = service.security_groups[0]
        assert group.id == "10"
        assert group.name == "default"
        assert group.location == "Delhi"
        assert group.is_default is True
        assert group.is_all_traffic_rule is True
        assert len(group.rules) == 1
        assert group.rules[0].rule_type == "Inbound"

    @patch(
        "prowler.providers.e2enetworks.services.securitygroup.securitygroup_service.E2eNetworksService.__init__"
    )
    def test_fetch_security_groups_ignores_non_list_response(self, mock_super_init):
        mock_super_init.return_value = None

        provider = MagicMock()
        provider.session.locations = ["Delhi"]
        service = SecurityGroups.__new__(SecurityGroups)
        service.provider = provider
        service.client = MagicMock()
        service.security_groups = []

        service.client.get_data.return_value = {"error": "unexpected"}

        service._fetch_security_groups()

        assert service.security_groups == []
