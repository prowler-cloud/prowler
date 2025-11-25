from unittest import mock
from uuid import uuid4

from prowler.providers.stackit.services.iaas.iaas_service import (
    SecurityGroup,
    SecurityGroupRule,
)
from tests.providers.stackit.stackit_fixtures import (
    STACKIT_PROJECT_ID,
    set_mocked_stackit_provider,
)


class Test_iaas_security_group_ssh_unrestricted:
    def test_no_security_groups(self):
        """Test with no security groups - should return empty results."""
        iaas_client = mock.MagicMock
        iaas_client.security_groups = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_stackit_provider(),
            ),
            mock.patch(
                "prowler.providers.stackit.services.iaas.iaas_service.IaaSService",
                new=iaas_client,
            ) as service_client,
            mock.patch(
                "prowler.providers.stackit.services.iaas.iaas_client.iaas_client",
                new=service_client,
            ),
        ):
            from prowler.providers.stackit.services.iaas.iaas_security_group_ssh_unrestricted.iaas_security_group_ssh_unrestricted import (
                iaas_security_group_ssh_unrestricted,
            )

            check = iaas_security_group_ssh_unrestricted()
            result = check.execute()
            assert len(result) == 0

    def test_security_group_not_in_use(self):
        """Test security group not in use - should be skipped."""
        iaas_client = mock.MagicMock
        security_group_name = "test-security-group"
        security_group_id = str(uuid4())

        iaas_client.security_groups = [
            SecurityGroup(
                id=security_group_id,
                name=security_group_name,
                project_id=STACKIT_PROJECT_ID,
                region="eu01",
                rules=[
                    SecurityGroupRule(
                        id="rule-1",
                        direction="ingress",
                        protocol="tcp",
                        ip_range="0.0.0.0/0",
                        port_range_min=22,
                        port_range_max=22,
                    )
                ],
                in_use=False,  # Not in use - should be skipped
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_stackit_provider(),
            ),
            mock.patch(
                "prowler.providers.stackit.services.iaas.iaas_service.IaaSService",
                new=iaas_client,
            ) as service_client,
            mock.patch(
                "prowler.providers.stackit.services.iaas.iaas_client.iaas_client",
                new=service_client,
            ),
        ):
            from prowler.providers.stackit.services.iaas.iaas_security_group_ssh_unrestricted.iaas_security_group_ssh_unrestricted import (
                iaas_security_group_ssh_unrestricted,
            )

            check = iaas_security_group_ssh_unrestricted()
            result = check.execute()
            assert len(result) == 0

    def test_security_group_no_rules(self):
        """Test security group with no rules - should PASS."""
        iaas_client = mock.MagicMock
        security_group_name = "test-security-group"
        security_group_id = str(uuid4())

        iaas_client.security_groups = [
            SecurityGroup(
                id=security_group_id,
                name=security_group_name,
                project_id=STACKIT_PROJECT_ID,
                region="eu01",
                rules=[],
                in_use=True,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_stackit_provider(),
            ),
            mock.patch(
                "prowler.providers.stackit.services.iaas.iaas_service.IaaSService",
                new=iaas_client,
            ) as service_client,
            mock.patch(
                "prowler.providers.stackit.services.iaas.iaas_client.iaas_client",
                new=service_client,
            ),
        ):
            from prowler.providers.stackit.services.iaas.iaas_security_group_ssh_unrestricted.iaas_security_group_ssh_unrestricted import (
                iaas_security_group_ssh_unrestricted,
            )

            check = iaas_security_group_ssh_unrestricted()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Security group '{security_group_name}' does not allow unrestricted SSH access."
            )
            assert result[0].resource_id == security_group_id
            assert result[0].resource_name == security_group_name
            assert result[0].location == "eu01"

    def test_security_group_ssh_unrestricted_exact_port(self):
        """Test security group with SSH port 22 unrestricted - should FAIL."""
        iaas_client = mock.MagicMock
        security_group_name = "test-security-group"
        security_group_id = str(uuid4())

        iaas_client.security_groups = [
            SecurityGroup(
                id=security_group_id,
                name=security_group_name,
                project_id=STACKIT_PROJECT_ID,
                region="eu01",
                rules=[
                    SecurityGroupRule(
                        id="rule-1",
                        direction="ingress",
                        protocol="tcp",
                        ip_range="0.0.0.0/0",
                        port_range_min=22,
                        port_range_max=22,
                    )
                ],
                in_use=True,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_stackit_provider(),
            ),
            mock.patch(
                "prowler.providers.stackit.services.iaas.iaas_service.IaaSService",
                new=iaas_client,
            ) as service_client,
            mock.patch(
                "prowler.providers.stackit.services.iaas.iaas_client.iaas_client",
                new=service_client,
            ),
        ):
            from prowler.providers.stackit.services.iaas.iaas_security_group_ssh_unrestricted.iaas_security_group_ssh_unrestricted import (
                iaas_security_group_ssh_unrestricted,
            )

            check = iaas_security_group_ssh_unrestricted()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "allows unrestricted SSH access" in result[0].status_extended
            assert result[0].resource_id == security_group_id
            assert result[0].resource_name == security_group_name
            assert result[0].location == "eu01"

    def test_security_group_ssh_unrestricted_port_range(self):
        """Test security group with port range including SSH - should FAIL."""
        iaas_client = mock.MagicMock
        security_group_name = "test-security-group"
        security_group_id = str(uuid4())

        iaas_client.security_groups = [
            SecurityGroup(
                id=security_group_id,
                name=security_group_name,
                project_id=STACKIT_PROJECT_ID,
                region="eu01",
                rules=[
                    SecurityGroupRule(
                        id="rule-1",
                        direction="ingress",
                        protocol="tcp",
                        ip_range="0.0.0.0/0",
                        port_range_min=20,
                        port_range_max=25,
                    )
                ],
                in_use=True,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_stackit_provider(),
            ),
            mock.patch(
                "prowler.providers.stackit.services.iaas.iaas_service.IaaSService",
                new=iaas_client,
            ) as service_client,
            mock.patch(
                "prowler.providers.stackit.services.iaas.iaas_client.iaas_client",
                new=service_client,
            ),
        ):
            from prowler.providers.stackit.services.iaas.iaas_security_group_ssh_unrestricted.iaas_security_group_ssh_unrestricted import (
                iaas_security_group_ssh_unrestricted,
            )

            check = iaas_security_group_ssh_unrestricted()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "allows unrestricted SSH access" in result[0].status_extended
            assert result[0].resource_id == security_group_id
            assert result[0].resource_name == security_group_name

    def test_security_group_ssh_restricted_ip(self):
        """Test security group with SSH restricted to specific IP - should PASS."""
        iaas_client = mock.MagicMock
        security_group_name = "test-security-group"
        security_group_id = str(uuid4())

        iaas_client.security_groups = [
            SecurityGroup(
                id=security_group_id,
                name=security_group_name,
                project_id=STACKIT_PROJECT_ID,
                region="eu01",
                rules=[
                    SecurityGroupRule(
                        id="rule-1",
                        direction="ingress",
                        protocol="tcp",
                        ip_range="10.0.0.0/8",
                        port_range_min=22,
                        port_range_max=22,
                    )
                ],
                in_use=True,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_stackit_provider(),
            ),
            mock.patch(
                "prowler.providers.stackit.services.iaas.iaas_service.IaaSService",
                new=iaas_client,
            ) as service_client,
            mock.patch(
                "prowler.providers.stackit.services.iaas.iaas_client.iaas_client",
                new=service_client,
            ),
        ):
            from prowler.providers.stackit.services.iaas.iaas_security_group_ssh_unrestricted.iaas_security_group_ssh_unrestricted import (
                iaas_security_group_ssh_unrestricted,
            )

            check = iaas_security_group_ssh_unrestricted()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "does not allow unrestricted SSH access" in result[0].status_extended

    def test_security_group_different_port(self):
        """Test security group with unrestricted access but different port - should PASS."""
        iaas_client = mock.MagicMock
        security_group_name = "test-security-group"
        security_group_id = str(uuid4())

        iaas_client.security_groups = [
            SecurityGroup(
                id=security_group_id,
                name=security_group_name,
                project_id=STACKIT_PROJECT_ID,
                region="eu01",
                rules=[
                    SecurityGroupRule(
                        id="rule-1",
                        direction="ingress",
                        protocol="tcp",
                        ip_range="0.0.0.0/0",
                        port_range_min=80,
                        port_range_max=80,
                    )
                ],
                in_use=True,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_stackit_provider(),
            ),
            mock.patch(
                "prowler.providers.stackit.services.iaas.iaas_service.IaaSService",
                new=iaas_client,
            ) as service_client,
            mock.patch(
                "prowler.providers.stackit.services.iaas.iaas_client.iaas_client",
                new=service_client,
            ),
        ):
            from prowler.providers.stackit.services.iaas.iaas_security_group_ssh_unrestricted.iaas_security_group_ssh_unrestricted import (
                iaas_security_group_ssh_unrestricted,
            )

            check = iaas_security_group_ssh_unrestricted()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_security_group_egress_rule(self):
        """Test security group with egress rule - should PASS."""
        iaas_client = mock.MagicMock
        security_group_name = "test-security-group"
        security_group_id = str(uuid4())

        iaas_client.security_groups = [
            SecurityGroup(
                id=security_group_id,
                name=security_group_name,
                project_id=STACKIT_PROJECT_ID,
                region="eu01",
                rules=[
                    SecurityGroupRule(
                        id="rule-1",
                        direction="egress",  # Egress, not ingress
                        protocol="tcp",
                        ip_range="0.0.0.0/0",
                        port_range_min=22,
                        port_range_max=22,
                    )
                ],
                in_use=True,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_stackit_provider(),
            ),
            mock.patch(
                "prowler.providers.stackit.services.iaas.iaas_service.IaaSService",
                new=iaas_client,
            ) as service_client,
            mock.patch(
                "prowler.providers.stackit.services.iaas.iaas_client.iaas_client",
                new=service_client,
            ),
        ):
            from prowler.providers.stackit.services.iaas.iaas_security_group_ssh_unrestricted.iaas_security_group_ssh_unrestricted import (
                iaas_security_group_ssh_unrestricted,
            )

            check = iaas_security_group_ssh_unrestricted()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_security_group_none_protocol(self):
        """Test security group with None protocol (all protocols) - should FAIL."""
        iaas_client = mock.MagicMock
        security_group_name = "test-security-group"
        security_group_id = str(uuid4())

        iaas_client.security_groups = [
            SecurityGroup(
                id=security_group_id,
                name=security_group_name,
                project_id=STACKIT_PROJECT_ID,
                region="eu01",
                rules=[
                    SecurityGroupRule(
                        id="rule-1",
                        direction="ingress",
                        protocol=None,  # None means all protocols (includes TCP)
                        ip_range="0.0.0.0/0",
                        port_range_min=22,
                        port_range_max=22,
                    )
                ],
                in_use=True,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_stackit_provider(),
            ),
            mock.patch(
                "prowler.providers.stackit.services.iaas.iaas_service.IaaSService",
                new=iaas_client,
            ) as service_client,
            mock.patch(
                "prowler.providers.stackit.services.iaas.iaas_client.iaas_client",
                new=service_client,
            ),
        ):
            from prowler.providers.stackit.services.iaas.iaas_security_group_ssh_unrestricted.iaas_security_group_ssh_unrestricted import (
                iaas_security_group_ssh_unrestricted,
            )

            check = iaas_security_group_ssh_unrestricted()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_security_group_none_ip_range(self):
        """Test security group with None ip_range (unrestricted) - should FAIL."""
        iaas_client = mock.MagicMock
        security_group_name = "test-security-group"
        security_group_id = str(uuid4())

        iaas_client.security_groups = [
            SecurityGroup(
                id=security_group_id,
                name=security_group_name,
                project_id=STACKIT_PROJECT_ID,
                region="eu01",
                rules=[
                    SecurityGroupRule(
                        id="rule-1",
                        direction="ingress",
                        protocol="tcp",
                        ip_range=None,  # None means unrestricted access
                        port_range_min=22,
                        port_range_max=22,
                    )
                ],
                in_use=True,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_stackit_provider(),
            ),
            mock.patch(
                "prowler.providers.stackit.services.iaas.iaas_service.IaaSService",
                new=iaas_client,
            ) as service_client,
            mock.patch(
                "prowler.providers.stackit.services.iaas.iaas_client.iaas_client",
                new=service_client,
            ),
        ):
            from prowler.providers.stackit.services.iaas.iaas_security_group_ssh_unrestricted.iaas_security_group_ssh_unrestricted import (
                iaas_security_group_ssh_unrestricted,
            )

            check = iaas_security_group_ssh_unrestricted()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_security_group_none_port_range(self):
        """Test security group with None port range (all ports) - should FAIL."""
        iaas_client = mock.MagicMock
        security_group_name = "test-security-group"
        security_group_id = str(uuid4())

        iaas_client.security_groups = [
            SecurityGroup(
                id=security_group_id,
                name=security_group_name,
                project_id=STACKIT_PROJECT_ID,
                region="eu01",
                rules=[
                    SecurityGroupRule(
                        id="rule-1",
                        direction="ingress",
                        protocol="tcp",
                        ip_range="0.0.0.0/0",
                        port_range_min=None,  # None means all ports
                        port_range_max=None,
                    )
                ],
                in_use=True,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_stackit_provider(),
            ),
            mock.patch(
                "prowler.providers.stackit.services.iaas.iaas_service.IaaSService",
                new=iaas_client,
            ) as service_client,
            mock.patch(
                "prowler.providers.stackit.services.iaas.iaas_client.iaas_client",
                new=service_client,
            ),
        ):
            from prowler.providers.stackit.services.iaas.iaas_security_group_ssh_unrestricted.iaas_security_group_ssh_unrestricted import (
                iaas_security_group_ssh_unrestricted,
            )

            check = iaas_security_group_ssh_unrestricted()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
