from unittest import mock

from prowler.providers.e2enetworks.services.securitygroup.securitygroup_service import (
    NodeSecurityGroup,
    SecurityGroupRule,
)
from tests.providers.e2enetworks.e2enetworks_fixtures import (
    set_mocked_e2enetworks_provider,
)

CLIENT_PATH = "prowler.providers.e2enetworks.services.securitygroup.securitygroup_restrictive_default.securitygroup_restrictive_default.securitygroup_client"


class Test_securitygroup_restrictive_default:
    def test_no_node_security_groups(self):
        client = mock.MagicMock()
        client.node_security_groups = []
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.securitygroup.securitygroup_restrictive_default.securitygroup_restrictive_default import (
                securitygroup_restrictive_default,
            )

            assert securitygroup_restrictive_default().execute() == []

    def test_securitygroup_restrictive_default_compliant(self):
        client = mock.MagicMock()
        client.node_security_groups = [
            NodeSecurityGroup(
                node_id="1",
                node_name="ok-node",
                vm_id="vm-1",
                location="Delhi",
                security_group_id="sg-1",
                name="custom",
                is_default=False,
                rules=[],
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.securitygroup.securitygroup_restrictive_default.securitygroup_restrictive_default import (
                securitygroup_restrictive_default,
            )

            findings = securitygroup_restrictive_default().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"

    def test_securitygroup_restrictive_default_non_compliant(self):
        client = mock.MagicMock()
        client.node_security_groups = [
            NodeSecurityGroup(
                node_id="2",
                node_name="bad-node",
                vm_id="vm-2",
                location="Delhi",
                security_group_id="sg-2",
                name="default",
                is_default=True,
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
            from prowler.providers.e2enetworks.services.securitygroup.securitygroup_restrictive_default.securitygroup_restrictive_default import (
                securitygroup_restrictive_default,
            )

            findings = securitygroup_restrictive_default().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
