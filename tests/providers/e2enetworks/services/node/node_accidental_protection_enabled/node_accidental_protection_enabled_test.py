from unittest import mock

from prowler.providers.e2enetworks.services.node.node_service import (
    Node,
)
from tests.providers.e2enetworks.e2enetworks_fixtures import (
    set_mocked_e2enetworks_provider,
)

CLIENT_PATH = "prowler.providers.e2enetworks.services.node.node_accidental_protection_enabled.node_accidental_protection_enabled.node_client"


class Test_node_accidental_protection_enabled:
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
            from prowler.providers.e2enetworks.services.node.node_accidental_protection_enabled.node_accidental_protection_enabled import (
                node_accidental_protection_enabled,
            )

            assert node_accidental_protection_enabled().execute() == []

    def test_node_accidental_protection_enabled_compliant(self):
        client = mock.MagicMock()
        client.nodes = [
            Node(
                id="1",
                name="ok",
                status="Running",
                location="Delhi",
                vm_id="1",
                is_accidental_protection=True,
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.node.node_accidental_protection_enabled.node_accidental_protection_enabled import (
                node_accidental_protection_enabled,
            )

            findings = node_accidental_protection_enabled().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"

    def test_node_accidental_protection_enabled_non_compliant(self):
        client = mock.MagicMock()
        client.nodes = [
            Node(
                id="2",
                name="bad",
                status="Running",
                location="Delhi",
                vm_id="2",
                is_accidental_protection=False,
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.node.node_accidental_protection_enabled.node_accidental_protection_enabled import (
                node_accidental_protection_enabled,
            )

            findings = node_accidental_protection_enabled().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
