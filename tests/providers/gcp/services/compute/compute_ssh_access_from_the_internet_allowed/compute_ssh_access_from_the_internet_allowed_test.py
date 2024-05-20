from re import search
from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class Test_compute_firewall_ssh_access_from_the_internet_allowed:
    def test_compute_no_instances(self):
        compute_client = mock.MagicMock
        compute_client.firewalls = []

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_firewall_ssh_access_from_the_internet_allowed.compute_firewall_ssh_access_from_the_internet_allowed.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_firewall_ssh_access_from_the_internet_allowed.compute_firewall_ssh_access_from_the_internet_allowed import (
                compute_firewall_ssh_access_from_the_internet_allowed,
            )

            check = compute_firewall_ssh_access_from_the_internet_allowed()
            result = check.execute()
            assert len(result) == 0

    def test_one_compliant_rule_with_valid_port(self):
        from prowler.providers.gcp.services.compute.compute_service import Firewall

        firewall = Firewall(
            name="test",
            id="1234567890",
            source_ranges=["0.0.0.0/0"],
            direction="INGRESS",
            allowed_rules=[{"IPProtocol": "tcp", "ports": ["443"]}],
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.firewalls = [firewall]
        compute_client.region = "global"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_firewall_ssh_access_from_the_internet_allowed.compute_firewall_ssh_access_from_the_internet_allowed.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_firewall_ssh_access_from_the_internet_allowed.compute_firewall_ssh_access_from_the_internet_allowed import (
                compute_firewall_ssh_access_from_the_internet_allowed,
            )

            check = compute_firewall_ssh_access_from_the_internet_allowed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"Firewall {firewall.name} does not expose port 22",
                result[0].status_extended,
            )
            assert result[0].resource_id == firewall.id

    def test_one_compliant_rule_with_valid_port_range(self):
        from prowler.providers.gcp.services.compute.compute_service import Firewall

        firewall = Firewall(
            name="test",
            id="1234567890",
            source_ranges=["0.0.0.0/0"],
            direction="INGRESS",
            allowed_rules=[{"IPProtocol": "tcp", "ports": ["1-20"]}],
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.firewalls = [firewall]
        compute_client.region = "global"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_firewall_ssh_access_from_the_internet_allowed.compute_firewall_ssh_access_from_the_internet_allowed.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_firewall_ssh_access_from_the_internet_allowed.compute_firewall_ssh_access_from_the_internet_allowed import (
                compute_firewall_ssh_access_from_the_internet_allowed,
            )

            check = compute_firewall_ssh_access_from_the_internet_allowed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"Firewall {firewall.name} does not expose port 22",
                result[0].status_extended,
            )
            assert result[0].resource_id == firewall.id

    def test_one_compliant_rule_with_valid_source_range(self):
        from prowler.providers.gcp.services.compute.compute_service import Firewall

        firewall = Firewall(
            name="test",
            id="1234567890",
            source_ranges=["127.0.0.1/32"],
            direction="INGRESS",
            allowed_rules=[{"IPProtocol": "tcp", "ports": ["22"]}],
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.firewalls = [firewall]
        compute_client.region = "global"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_firewall_ssh_access_from_the_internet_allowed.compute_firewall_ssh_access_from_the_internet_allowed.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_firewall_ssh_access_from_the_internet_allowed.compute_firewall_ssh_access_from_the_internet_allowed import (
                compute_firewall_ssh_access_from_the_internet_allowed,
            )

            check = compute_firewall_ssh_access_from_the_internet_allowed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"Firewall {firewall.name} does not expose port 22",
                result[0].status_extended,
            )
            assert result[0].resource_id == firewall.id

    def test_one_compliant_rule_with_valid_protocol(self):
        from prowler.providers.gcp.services.compute.compute_service import Firewall

        firewall = Firewall(
            name="test",
            id="1234567890",
            source_ranges=["0.0.0.0/0"],
            direction="INGRESS",
            allowed_rules=[{"IPProtocol": "udp", "ports": ["22"]}],
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.firewalls = [firewall]
        compute_client.region = "global"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_firewall_ssh_access_from_the_internet_allowed.compute_firewall_ssh_access_from_the_internet_allowed.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_firewall_ssh_access_from_the_internet_allowed.compute_firewall_ssh_access_from_the_internet_allowed import (
                compute_firewall_ssh_access_from_the_internet_allowed,
            )

            check = compute_firewall_ssh_access_from_the_internet_allowed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"Firewall {firewall.name} does not expose port 22",
                result[0].status_extended,
            )
            assert result[0].resource_id == firewall.id

    def test_one_compliant_rule_with_valid_direction(self):
        from prowler.providers.gcp.services.compute.compute_service import Firewall

        firewall = Firewall(
            name="test",
            id="1234567890",
            source_ranges=["0.0.0.0/0"],
            direction="EGRESS",
            allowed_rules=[{"IPProtocol": "tcp", "ports": ["22"]}],
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.firewalls = [firewall]
        compute_client.region = "global"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_firewall_ssh_access_from_the_internet_allowed.compute_firewall_ssh_access_from_the_internet_allowed.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_firewall_ssh_access_from_the_internet_allowed.compute_firewall_ssh_access_from_the_internet_allowed import (
                compute_firewall_ssh_access_from_the_internet_allowed,
            )

            check = compute_firewall_ssh_access_from_the_internet_allowed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"Firewall {firewall.name} does not expose port 22",
                result[0].status_extended,
            )
            assert result[0].resource_id == firewall.id

    def test_one_non_compliant_rule_with_single_port(self):
        from prowler.providers.gcp.services.compute.compute_service import Firewall

        firewall = Firewall(
            name="test",
            id="1234567890",
            source_ranges=["0.0.0.0/0"],
            direction="INGRESS",
            allowed_rules=[{"IPProtocol": "tcp", "ports": ["22"]}],
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.firewalls = [firewall]
        compute_client.region = "global"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_firewall_ssh_access_from_the_internet_allowed.compute_firewall_ssh_access_from_the_internet_allowed.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_firewall_ssh_access_from_the_internet_allowed.compute_firewall_ssh_access_from_the_internet_allowed import (
                compute_firewall_ssh_access_from_the_internet_allowed,
            )

            check = compute_firewall_ssh_access_from_the_internet_allowed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"Firewall {firewall.name} does exposes port 22",
                result[0].status_extended,
            )
            assert result[0].resource_id == firewall.id

    def test_one_non_compliant_rule_with_port_range(self):
        from prowler.providers.gcp.services.compute.compute_service import Firewall

        firewall = Firewall(
            name="test",
            id="1234567890",
            source_ranges=["0.0.0.0/0"],
            direction="INGRESS",
            allowed_rules=[{"IPProtocol": "tcp", "ports": ["20-443"]}],
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.firewalls = [firewall]
        compute_client.region = "global"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_firewall_ssh_access_from_the_internet_allowed.compute_firewall_ssh_access_from_the_internet_allowed.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_firewall_ssh_access_from_the_internet_allowed.compute_firewall_ssh_access_from_the_internet_allowed import (
                compute_firewall_ssh_access_from_the_internet_allowed,
            )

            check = compute_firewall_ssh_access_from_the_internet_allowed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"Firewall {firewall.name} does exposes port 22",
                result[0].status_extended,
            )
            assert result[0].resource_id == firewall.id

    def test_one_non_compliant_with_all_ports_allowed(self):
        from prowler.providers.gcp.services.compute.compute_service import Firewall

        firewall = Firewall(
            name="test",
            id="1234567890",
            source_ranges=["0.0.0.0/0"],
            direction="INGRESS",
            allowed_rules=[{"IPProtocol": "tcp"}],
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.firewalls = [firewall]
        compute_client.region = "global"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_firewall_ssh_access_from_the_internet_allowed.compute_firewall_ssh_access_from_the_internet_allowed.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_firewall_ssh_access_from_the_internet_allowed.compute_firewall_ssh_access_from_the_internet_allowed import (
                compute_firewall_ssh_access_from_the_internet_allowed,
            )

            check = compute_firewall_ssh_access_from_the_internet_allowed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"Firewall {firewall.name} does exposes port 22",
                result[0].status_extended,
            )
            assert result[0].resource_id == firewall.id

    def test_one_non_compliant_with_all_protocols_allowed(self):
        from prowler.providers.gcp.services.compute.compute_service import Firewall

        firewall = Firewall(
            name="test",
            id="1234567890",
            source_ranges=["0.0.0.0/0"],
            direction="INGRESS",
            allowed_rules=[{"IPProtocol": "all"}],
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.firewalls = [firewall]
        compute_client.region = "global"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_firewall_ssh_access_from_the_internet_allowed.compute_firewall_ssh_access_from_the_internet_allowed.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_firewall_ssh_access_from_the_internet_allowed.compute_firewall_ssh_access_from_the_internet_allowed import (
                compute_firewall_ssh_access_from_the_internet_allowed,
            )

            check = compute_firewall_ssh_access_from_the_internet_allowed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"Firewall {firewall.name} does exposes port 22",
                result[0].status_extended,
            )
            assert result[0].resource_id == firewall.id

    def test_one_non_compliant_with_2_rules(self):
        from prowler.providers.gcp.services.compute.compute_service import Firewall

        firewall = Firewall(
            name="test",
            id="1234567890",
            source_ranges=["0.0.0.0/0"],
            direction="INGRESS",
            allowed_rules=[
                {"IPProtocol": "udp", "ports": ["22"]},
                {"IPProtocol": "all"},
            ],
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.firewalls = [firewall]
        compute_client.region = "global"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_firewall_ssh_access_from_the_internet_allowed.compute_firewall_ssh_access_from_the_internet_allowed.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_firewall_ssh_access_from_the_internet_allowed.compute_firewall_ssh_access_from_the_internet_allowed import (
                compute_firewall_ssh_access_from_the_internet_allowed,
            )

            check = compute_firewall_ssh_access_from_the_internet_allowed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"Firewall {firewall.name} does exposes port 22",
                result[0].status_extended,
            )
            assert result[0].resource_id == firewall.id

    def test_one_compliant_with_3_rules(self):
        from prowler.providers.gcp.services.compute.compute_service import Firewall

        firewall = Firewall(
            name="test",
            id="1234567890",
            source_ranges=["0.0.0.0/0"],
            direction="INGRESS",
            allowed_rules=[
                {"IPProtocol": "udp", "ports": ["22"]},
                {"IPProtocol": "tcp", "ports": ["23"]},
                {"IPProtocol": "udp"},
            ],
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.firewalls = [firewall]
        compute_client.region = "global"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_firewall_ssh_access_from_the_internet_allowed.compute_firewall_ssh_access_from_the_internet_allowed.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_firewall_ssh_access_from_the_internet_allowed.compute_firewall_ssh_access_from_the_internet_allowed import (
                compute_firewall_ssh_access_from_the_internet_allowed,
            )

            check = compute_firewall_ssh_access_from_the_internet_allowed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"Firewall {firewall.name} does not expose port 22",
                result[0].status_extended,
            )
            assert result[0].resource_id == firewall.id
