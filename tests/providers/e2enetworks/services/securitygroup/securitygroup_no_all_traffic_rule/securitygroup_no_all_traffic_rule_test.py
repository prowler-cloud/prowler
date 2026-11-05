from unittest import mock

from prowler.providers.e2enetworks.services.securitygroup.securitygroup_service import (
    SecurityGroupResource,
)
from tests.providers.e2enetworks.e2enetworks_fixtures import (
    set_mocked_e2enetworks_provider,
)

CLIENT_PATH = "prowler.providers.e2enetworks.services.securitygroup.securitygroup_no_all_traffic_rule.securitygroup_no_all_traffic_rule.securitygroup_client"


class Test_securitygroup_no_all_traffic_rule:
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
            from prowler.providers.e2enetworks.services.securitygroup.securitygroup_no_all_traffic_rule.securitygroup_no_all_traffic_rule import (
                securitygroup_no_all_traffic_rule,
            )

            assert securitygroup_no_all_traffic_rule().execute() == []

    def test_securitygroup_no_all_traffic_rule_compliant(self):
        client = mock.MagicMock()
        client.security_groups = [
            SecurityGroupResource(
                id="1", name="ok", location="Delhi", is_all_traffic_rule=False
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.securitygroup.securitygroup_no_all_traffic_rule.securitygroup_no_all_traffic_rule import (
                securitygroup_no_all_traffic_rule,
            )

            findings = securitygroup_no_all_traffic_rule().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"

    def test_securitygroup_no_all_traffic_rule_non_compliant(self):
        client = mock.MagicMock()
        client.security_groups = [
            SecurityGroupResource(
                id="2", name="bad", location="Delhi", is_all_traffic_rule=True
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.securitygroup.securitygroup_no_all_traffic_rule.securitygroup_no_all_traffic_rule import (
                securitygroup_no_all_traffic_rule,
            )

            findings = securitygroup_no_all_traffic_rule().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
