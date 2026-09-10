from unittest import mock

from prowler.providers.e2enetworks.services.securitygroup.securitygroup_service import (
    SecurityGroupResource,
    SecurityGroupRule,
)
from tests.providers.e2enetworks.e2enetworks_fixtures import (
    set_mocked_e2enetworks_provider,
)

CLIENT_PATH = "prowler.providers.e2enetworks.services.securitygroup.securitygroup_no_inbound_any_all_ports.securitygroup_no_inbound_any_all_ports.securitygroup_client"


class Test_securitygroup_no_inbound_any_all_ports:
    def test_no_security_groups(self):
        client = mock.MagicMock()
        client.security_groups = []
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.securitygroup.securitygroup_no_inbound_any_all_ports.securitygroup_no_inbound_any_all_ports import (
                securitygroup_no_inbound_any_all_ports,
            )

            assert securitygroup_no_inbound_any_all_ports().execute() == []

    def test_securitygroup_no_inbound_any_all_ports_compliant(self):
        client = mock.MagicMock()
        client.security_groups = [
            SecurityGroupResource(
                id="1",
                name="ok",
                location="Delhi",
                rules=[
                    SecurityGroupRule(
                        id="2",
                        rule_type="inbound",
                        protocol_name="tcp",
                        port_range="443",
                        network="203.0.113.0/24",
                        network_cidr="203.0.113.0/24",
                    )
                ],
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.securitygroup.securitygroup_no_inbound_any_all_ports.securitygroup_no_inbound_any_all_ports import (
                securitygroup_no_inbound_any_all_ports,
            )

            findings = securitygroup_no_inbound_any_all_ports().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"

    def test_securitygroup_no_inbound_any_all_ports_non_compliant(self):
        client = mock.MagicMock()
        client.security_groups = [
            SecurityGroupResource(
                id="2",
                name="bad",
                location="Delhi",
                rules=[
                    SecurityGroupRule(
                        id="1",
                        rule_type="inbound",
                        protocol_name="all",
                        port_range="",
                        network="any",
                        network_cidr="",
                    )
                ],
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.securitygroup.securitygroup_no_inbound_any_all_ports.securitygroup_no_inbound_any_all_ports import (
                securitygroup_no_inbound_any_all_ports,
            )

            findings = securitygroup_no_inbound_any_all_ports().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
