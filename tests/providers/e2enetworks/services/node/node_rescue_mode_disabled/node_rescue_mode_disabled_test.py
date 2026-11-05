from unittest import mock

from prowler.providers.e2enetworks.services.node.node_service import (
    Node,
)
from tests.providers.e2enetworks.e2enetworks_fixtures import (
    set_mocked_e2enetworks_provider,
)

CLIENT_PATH = "prowler.providers.e2enetworks.services.node.node_rescue_mode_disabled.node_rescue_mode_disabled.node_client"


class Test_node_rescue_mode_disabled:
    def test_no_nodes(self):
        client = mock.MagicMock()
        client.nodes = []
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.node.node_rescue_mode_disabled.node_rescue_mode_disabled import (
                node_rescue_mode_disabled,
            )

            assert node_rescue_mode_disabled().execute() == []

    def test_node_rescue_mode_disabled_compliant(self):
        client = mock.MagicMock()
        client.nodes = [
            Node(
                id="1",
                name="ok",
                status="Running",
                location="Delhi",
                vm_id="1",
                rescue_mode_status="Disabled",
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.node.node_rescue_mode_disabled.node_rescue_mode_disabled import (
                node_rescue_mode_disabled,
            )

            findings = node_rescue_mode_disabled().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"

    def test_node_rescue_mode_disabled_non_compliant(self):
        client = mock.MagicMock()
        client.nodes = [
            Node(
                id="2",
                name="bad",
                status="Running",
                location="Delhi",
                vm_id="2",
                rescue_mode_status="Enabled",
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.node.node_rescue_mode_disabled.node_rescue_mode_disabled import (
                node_rescue_mode_disabled,
            )

            findings = node_rescue_mode_disabled().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
