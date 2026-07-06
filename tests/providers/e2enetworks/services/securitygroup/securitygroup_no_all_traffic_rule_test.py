from unittest import mock

from prowler.providers.e2enetworks.services.securitygroup.securitygroup_service import (
    SecurityGroupResource,
)
from tests.providers.e2enetworks.e2enetworks_fixtures import (
    set_mocked_e2enetworks_provider,
)


class TestSecurityGroupNoAllTrafficRuleCheck:
    def test_pass_and_fail(self):
        securitygroup_client = mock.MagicMock()
        securitygroup_client.security_groups = [
            SecurityGroupResource(
                id="1",
                name="restricted",
                location="Delhi",
                is_all_traffic_rule=False,
            ),
            SecurityGroupResource(
                id="2",
                name="open",
                location="Delhi",
                is_all_traffic_rule=True,
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(
                "prowler.providers.e2enetworks.services.securitygroup.securitygroup_no_all_traffic_rule.securitygroup_no_all_traffic_rule.securitygroup_client",
                new=securitygroup_client,
            ),
        ):
            from prowler.providers.e2enetworks.services.securitygroup.securitygroup_no_all_traffic_rule.securitygroup_no_all_traffic_rule import (
                securitygroup_no_all_traffic_rule,
            )

            findings = securitygroup_no_all_traffic_rule().execute()

            assert len(findings) == 2
            assert findings[0].status == "PASS"
            assert findings[0].resource_id == "1"
            assert findings[1].status == "FAIL"
            assert findings[1].resource_id == "2"
