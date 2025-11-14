from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.stackit.stackit_provider import StackitProvider


class IaaSService:
    """
    StackIT IaaS Service class to handle security group operations.

    This service uses the StackIT Python SDK to access IaaS resources
    using API token authentication.
    """

    def __init__(self, provider: StackitProvider):
        """
        Initialize the IaaS service.

        Args:
            provider: The StackIT provider instance
        """
        self.provider = provider
        self.project_id = provider.identity.project_id
        self.api_token = provider.session.get("api_token")

        # Initialize security groups list
        self.security_groups: list[SecurityGroup] = []

        # Fetch all security groups and their rules
        self._list_security_groups()

    def _get_stackit_client(self):
        """
        Get or create the StackIT IaaS client using the SDK.

        Returns:
            StackIT IaaS client configured with API token
        """
        try:
            # Import the StackIT SDK
            import os
            from stackit.core.configuration import Configuration
            from stackit.iaas import DefaultApi

            # The SDK expects STACKIT_SERVICE_ACCOUNT_TOKEN environment variable
            # Set it temporarily if not already set
            original_token = os.environ.get("STACKIT_SERVICE_ACCOUNT_TOKEN")
            os.environ["STACKIT_SERVICE_ACCOUNT_TOKEN"] = self.api_token

            try:
                # Create configuration - it will read from environment variable
                config = Configuration()

                # Create DefaultApi client directly with Configuration
                client = DefaultApi(config)
                return client
            finally:
                # Restore original environment variable
                if original_token is None:
                    os.environ.pop("STACKIT_SERVICE_ACCOUNT_TOKEN", None)
                else:
                    os.environ["STACKIT_SERVICE_ACCOUNT_TOKEN"] = original_token

        except ImportError as e:
            logger.error(
                f"StackIT SDK not available: {e}. "
                "Please ensure stackit-core and stackit-iaas are installed."
            )
            return None
        except Exception as e:
            logger.error(f"Error initializing StackIT IaaS client: {e}")
            return None

    def _list_security_groups(self):
        """
        List all security groups in the StackIT project and fetch their rules.

        This method populates the self.security_groups list with SecurityGroup
        objects containing information about each security group and its rules.
        """
        try:
            client = self._get_stackit_client()
            if not client:
                logger.warning(
                    "Cannot list security groups: StackIT IaaS client not available"
                )
                return

            # List all security groups using the SDK
            try:
                # Call the list security groups API
                # STACKIT has regions: eu01 (Germany South) and eu02 (Austria West)
                response = client.list_security_groups(
                    project_id=self.project_id, region="eu01"
                )

                # Extract security groups from response
                if hasattr(response, "items"):
                    security_groups_list = response.items
                elif isinstance(response, dict):
                    security_groups_list = response.get("items", [])
                elif isinstance(response, list):
                    security_groups_list = response
                else:
                    logger.warning(
                        f"Unexpected response type from list_security_groups: {type(response)}"
                    )
                    security_groups_list = []

            except Exception as e:
                logger.error(f"Error listing security groups via SDK: {e}")
                return

            # Process each security group
            for sg_data in security_groups_list:
                try:
                    # Extract security group information
                    if hasattr(sg_data, "id"):
                        sg_id = sg_data.id
                        sg_name = getattr(sg_data, "name", sg_id)
                        region = getattr(sg_data, "region", "eu01")
                    elif isinstance(sg_data, dict):
                        sg_id = sg_data.get("id", "")
                        sg_name = sg_data.get("name", sg_id)
                        region = sg_data.get("region", "eu01")
                    else:
                        logger.warning(
                            f"Unexpected security group data type: {type(sg_data)}"
                        )
                        continue

                    # Get security group rules
                    rules = self._list_security_group_rules(client, sg_id)

                    # Create SecurityGroup object
                    security_group = SecurityGroup(
                        id=sg_id,
                        name=sg_name,
                        project_id=self.project_id,
                        region=region,
                        rules=rules,
                    )
                    self.security_groups.append(security_group)

                except Exception as e:
                    logger.error(f"Error processing security group: {e}")
                    continue

            logger.info(
                f"Successfully listed {len(self.security_groups)} security groups"
            )

        except Exception as e:
            logger.error(f"Error listing StackIT IaaS security groups: {e}")

    def _list_security_group_rules(
        self, client, security_group_id: str
    ) -> list["SecurityGroupRule"]:
        """
        List all rules for a specific security group.

        Args:
            client: The StackIT IaaS client
            security_group_id: The ID of the security group

        Returns:
            list: List of SecurityGroupRule objects
        """
        rules = []
        try:
            # Get security group rules via SDK
            response = client.list_security_group_rules(
                project_id=self.project_id,
                security_group_id=security_group_id,
                region="eu01",
            )

            # Extract rules from response
            if hasattr(response, "items"):
                rules_list = response.items
            elif isinstance(response, dict):
                rules_list = response.get("items", [])
            elif isinstance(response, list):
                rules_list = response
            else:
                rules_list = []

            # Process each rule
            for rule_data in rules_list:
                try:
                    if hasattr(rule_data, "id"):
                        rule = SecurityGroupRule(
                            id=getattr(rule_data, "id", ""),
                            direction=getattr(rule_data, "direction", ""),
                            protocol=getattr(rule_data, "protocol", ""),
                            ip_range=getattr(rule_data, "ip_range", ""),
                            port_range_min=getattr(
                                rule_data, "port_range_min", None
                            ),
                            port_range_max=getattr(
                                rule_data, "port_range_max", None
                            ),
                        )
                    elif isinstance(rule_data, dict):
                        rule = SecurityGroupRule(
                            id=rule_data.get("id", ""),
                            direction=rule_data.get("direction", ""),
                            protocol=rule_data.get("protocol", ""),
                            ip_range=rule_data.get("ip_range", ""),
                            port_range_min=rule_data.get("port_range_min"),
                            port_range_max=rule_data.get("port_range_max"),
                        )
                    else:
                        continue

                    rules.append(rule)

                except Exception as e:
                    logger.debug(f"Error processing rule: {e}")
                    continue

        except Exception as e:
            logger.debug(
                f"Error listing rules for security group {security_group_id}: {e}"
            )

        return rules


class SecurityGroup(BaseModel):
    """
    Represents a StackIT IaaS Security Group.

    Attributes:
        id: The unique identifier of the security group
        name: The name of the security group
        project_id: The StackIT project ID containing the security group
        region: The region where the security group is located
        rules: List of security group rules
    """

    id: str
    name: str
    project_id: str
    region: str = "eu01"
    rules: list["SecurityGroupRule"] = []


class SecurityGroupRule(BaseModel):
    """
    Represents a Security Group Rule.

    Attributes:
        id: The unique identifier of the rule
        direction: The direction of the rule (ingress/egress)
        protocol: The protocol (tcp/udp/icmp/all)
        ip_range: The IP range (CIDR notation)
        port_range_min: The minimum port number
        port_range_max: The maximum port number
    """

    id: str
    direction: str
    protocol: str
    ip_range: str
    port_range_min: int = None
    port_range_max: int = None

    def is_unrestricted(self) -> bool:
        """Check if the rule allows access from anywhere (0.0.0.0/0 or ::/0)."""
        return self.ip_range in ["0.0.0.0/0", "::/0"]

    def is_ingress(self) -> bool:
        """Check if the rule is an ingress rule."""
        return self.direction.lower() == "ingress"

    def is_tcp(self) -> bool:
        """Check if the rule is TCP protocol."""
        return self.protocol.lower() in ["tcp", "all"]

    def includes_port(self, port: int) -> bool:
        """Check if the rule includes a specific port."""
        if self.port_range_min is None or self.port_range_max is None:
            # If no port range specified, rule applies to all ports
            return True
        return self.port_range_min <= port <= self.port_range_max
