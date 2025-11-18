import contextlib
import os
import sys
import warnings
from typing import Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.stackit.exceptions.exceptions import StackITInvalidTokenError
from prowler.providers.stackit.stackit_provider import StackitProvider


@contextlib.contextmanager
def suppress_stderr():
    """Context manager to suppress stderr output."""
    original_stderr = sys.stderr
    try:
        sys.stderr = open(os.devnull, 'w')
        yield
    finally:
        sys.stderr.close()
        sys.stderr = original_stderr


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

        # Initialize server NICs list and used security group IDs
        self.server_nics: list = []
        self.public_nic_ids: set[str] = set()  # NICs with public IPs
        self.in_use_sg_ids: set[str] = set()

        # Fetch public IPs first to determine which NICs are publicly accessible
        self._list_public_ips()

        # Fetch all server NICs to determine which security groups are in use
        self._list_server_nics()

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
            from stackit.core.configuration import Configuration
            from stackit.iaas import DefaultApi

            # Suppress StackIT SDK deprecation warnings and print() messages to stderr
            # The SDK prints warnings directly to stderr which can't be caught by warnings module
            with suppress_stderr(), warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=DeprecationWarning)
                warnings.filterwarnings("ignore", category=FutureWarning)

                # Pass the API token directly to Configuration (thread-safe approach)
                # This avoids manipulating global environment variables
                config = Configuration(service_account_token=self.api_token)

                # Create DefaultApi client directly with Configuration
                client = DefaultApi(config)

            return client

        except ImportError as e:
            logger.error(
                f"StackIT SDK not available: {e}. "
                "Please ensure stackit-core and stackit-iaas are installed."
            )
            return None
        except Exception as e:
            logger.error(f"Error initializing StackIT IaaS client: {e}")
            return None

    def _handle_api_call(self, api_function, *args, **kwargs):
        """
        Centralized API call handler with authentication error detection.

        Args:
            api_function: The API function to call
            *args: Positional arguments to pass to the API function
            **kwargs: Keyword arguments to pass to the API function

        Returns:
            The API response

        Raises:
            StackITInvalidTokenError: If authentication fails (401)
        """
        try:
            # Suppress StackIT SDK stderr warnings and deprecation warnings during API calls
            with suppress_stderr(), warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=DeprecationWarning)
                warnings.filterwarnings("ignore", category=FutureWarning)
                return api_function(*args, **kwargs)
        except Exception as e:
            # Check if this is an authentication error (401 Unauthorized)
            if hasattr(e, "status") and e.status == 401:
                logger.error(f"Authentication failed when calling StackIT API: {e}")
                raise StackITInvalidTokenError(
                    file=os.path.basename(__file__),
                    original_exception=e,
                    message="StackIT API token is invalid or has expired. Please generate a new token.",
                )
            # Re-raise other exceptions
            raise

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

            # Call the list security groups API with centralized error handling
            response = self._handle_api_call(
                client.list_security_groups, project_id=self.project_id
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
                        in_use=sg_id in self.in_use_sg_ids,
                    )
                    self.security_groups.append(security_group)

                except Exception as e:
                    logger.error(f"Error processing security group: {e}")
                    continue

            logger.info(
                f"Successfully listed {len(self.security_groups)} security groups"
            )

        except StackITInvalidTokenError:
            # Re-raise authentication errors so they propagate to the user
            raise
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
                        # Extract protocol name from Protocol object
                        protocol_obj = getattr(rule_data, "protocol", None)
                        protocol_name = None
                        if protocol_obj and hasattr(protocol_obj, "name"):
                            protocol_name = protocol_obj.name

                        # Extract port range from PortRange object
                        port_range_obj = getattr(rule_data, "port_range", None)
                        port_min = None
                        port_max = None
                        if port_range_obj:
                            if hasattr(port_range_obj, "min"):
                                port_min = port_range_obj.min
                            if hasattr(port_range_obj, "max"):
                                port_max = port_range_obj.max

                        rule = SecurityGroupRule(
                            id=getattr(rule_data, "id", ""),
                            direction=getattr(rule_data, "direction", ""),
                            protocol=protocol_name,
                            ip_range=getattr(rule_data, "ip_range", None),
                            port_range_min=port_min,
                            port_range_max=port_max,
                            description=getattr(rule_data, "description", None),
                            remote_security_group_id=getattr(
                                rule_data, "remote_security_group_id", None
                            ),
                        )
                    elif isinstance(rule_data, dict):
                        # Handle dict response (if API returns dict instead of objects)
                        protocol_data = rule_data.get("protocol")
                        protocol_name = None
                        if isinstance(protocol_data, dict):
                            protocol_name = protocol_data.get("name")
                        elif isinstance(protocol_data, str):
                            protocol_name = protocol_data

                        port_range_data = rule_data.get("port_range")
                        port_min = None
                        port_max = None
                        if isinstance(port_range_data, dict):
                            port_min = port_range_data.get("min")
                            port_max = port_range_data.get("max")

                        rule = SecurityGroupRule(
                            id=rule_data.get("id", ""),
                            direction=rule_data.get("direction", ""),
                            protocol=protocol_name,
                            ip_range=rule_data.get("ip_range"),
                            port_range_min=port_min,
                            port_range_max=port_max,
                            description=rule_data.get("description"),
                            remote_security_group_id=rule_data.get(
                                "remote_security_group_id"
                            ),
                        )
                    else:
                        continue

                    rules.append(rule)
                    logger.debug(
                        f"Parsed rule: id={rule.id}, direction={rule.direction}, "
                        f"protocol={rule.protocol}, ip_range={rule.ip_range}, "
                        f"ports={rule.port_range_min}-{rule.port_range_max}, "
                        f"remote_sg={rule.remote_security_group_id}"
                    )

                except Exception as e:
                    logger.debug(f"Error processing rule: {e}")
                    continue

        except Exception as e:
            logger.debug(
                f"Error listing rules for security group {security_group_id}: {e}"
            )

        return rules

    def _list_public_ips(self):
        """
        List all public IPs in the StackIT project and build a set of NIC IDs
        that have public IPs attached.

        This method populates self.public_nic_ids with the NIC IDs that are
        publicly accessible via public IP addresses.
        """
        try:
            client = self._get_stackit_client()
            if not client:
                logger.warning(
                    "Cannot list public IPs: StackIT IaaS client not available"
                )
                return

            # Call the list public IPs API with centralized error handling
            response = self._handle_api_call(
                client.list_public_ips, project_id=self.project_id
            )

            # Extract public IPs from response
            if hasattr(response, "items"):
                public_ips_list = response.items
            elif isinstance(response, dict):
                public_ips_list = response.get("items", [])
            elif isinstance(response, list):
                public_ips_list = response
            else:
                logger.warning(
                    f"Unexpected response type from list_public_ips: {type(response)}"
                )
                public_ips_list = []

            # Extract NIC IDs that have public IPs
            for public_ip in public_ips_list:
                try:
                    if hasattr(public_ip, "network_interface"):
                        nic_id = public_ip.network_interface
                    elif isinstance(public_ip, dict):
                        nic_id = public_ip.get(
                            "network_interface"
                        ) or public_ip.get("networkInterface")
                    else:
                        continue

                    if nic_id:
                        self.public_nic_ids.add(nic_id)

                except Exception as e:
                    logger.debug(f"Error extracting NIC ID from public IP: {e}")
                    continue

            logger.info(
                f"Successfully listed {len(public_ips_list)} public IPs "
                f"attached to {len(self.public_nic_ids)} NICs."
            )

        except StackITInvalidTokenError:
            # Re-raise authentication errors so they propagate to the user
            raise
        except Exception as e:
            logger.error(f"Error listing StackIT public IPs: {e}")

    def _list_server_nics(self):
        """
        List all server network interfaces (NICs) in the StackIT project.

        This method fetches all NICs and determines which security groups are
        actively in use by checking which security groups are attached to NICs.
        """
        try:
            client = self._get_stackit_client()
            if not client:
                logger.warning(
                    "Cannot list server NICs: StackIT IaaS client not available"
                )
                return

            # Call the list project NICs API with centralized error handling
            response = self._handle_api_call(
                client.list_project_nics, project_id=self.project_id
            )

            # Extract NICs from response
            if hasattr(response, "items"):
                nics_list = response.items
            elif isinstance(response, dict):
                nics_list = response.get("items", [])
            elif isinstance(response, list):
                nics_list = response
            else:
                logger.warning(
                    f"Unexpected response type from list_project_nics: {type(response)}"
                )
                nics_list = []

            self.server_nics = nics_list

            # Extract security group IDs that are in use (on public NICs only)
            self.in_use_sg_ids = self._get_used_security_group_ids()

            # Count NICs with public IPs for logging
            public_nic_count = sum(
                1
                for nic in self.server_nics
                if (
                    (hasattr(nic, "id") and nic.id in self.public_nic_ids)
                    or (
                        isinstance(nic, dict)
                        and nic.get("id") in self.public_nic_ids
                    )
                )
            )

            logger.info(
                f"Successfully listed {len(self.server_nics)} NICs "
                f"({public_nic_count} with public IPs). "
                f"Found {len(self.in_use_sg_ids)} security groups attached to public NICs."
            )

        except StackITInvalidTokenError:
            # Re-raise authentication errors so they propagate to the user
            raise
        except Exception as e:
            logger.error(f"Error listing StackIT server NICs: {e}")

    def _get_used_security_group_ids(self) -> set[str]:
        """
        Get the set of security group IDs that are actively attached to NICs
        with public IP addresses (internet-accessible).

        Only security groups on NICs with public IPs are considered "in use"
        for security checks, as private NICs are not reachable from the internet.

        Returns:
            set[str]: Set of security group IDs that are attached to public NICs
        """
        used_sg_ids = set()

        for nic in self.server_nics:
            try:
                # Get the NIC ID
                if hasattr(nic, "id"):
                    nic_id = nic.id
                elif isinstance(nic, dict):
                    nic_id = nic.get("id")
                else:
                    continue

                # Only consider security groups on NICs with public IPs
                if nic_id not in self.public_nic_ids:
                    continue

                # Extract security groups from NIC
                if hasattr(nic, "security_groups"):
                    sg_list = nic.security_groups
                elif isinstance(nic, dict):
                    sg_list = nic.get("security_groups", [])
                else:
                    continue

                # Add all security group IDs to the set
                if sg_list:
                    for sg_id in sg_list:
                        if sg_id:  # Ignore None or empty strings
                            used_sg_ids.add(sg_id)

            except Exception as e:
                logger.debug(f"Error extracting security groups from NIC: {e}")
                continue

        return used_sg_ids


class SecurityGroupRule(BaseModel):
    """
    Represents a Security Group Rule.

    Attributes:
        id: The unique identifier of the rule
        direction: The direction of the rule (ingress/egress)
        protocol: The protocol (tcp/udp/icmp/all) - can be None for some rules
        ip_range: The IP range (CIDR notation) - can be None for some rules
        port_range_min: The minimum port number
        port_range_max: The maximum port number
        description: The user-defined description/name of the rule (optional)
        remote_security_group_id: The ID of a security group to allow traffic from (optional)
    """

    id: str
    direction: str
    protocol: Optional[str] = None
    ip_range: Optional[str] = None
    port_range_min: Optional[int] = None
    port_range_max: Optional[int] = None
    description: Optional[str] = None
    remote_security_group_id: Optional[str] = None

    def is_unrestricted(self) -> bool:
        """Check if the rule allows access from anywhere (0.0.0.0/0, ::/0, or None for unrestricted)."""
        # If remote_security_group_id is set, the rule only allows traffic from that security group
        # This is NOT unrestricted access - it's restricted to instances in the same security group
        if self.remote_security_group_id is not None:
            return False

        # None means no IP restriction (allows all sources) - this is unrestricted!
        if self.ip_range is None:
            return True
        # Explicit unrestricted ranges
        return self.ip_range in ["0.0.0.0/0", "::/0"]

    def is_ingress(self) -> bool:
        """Check if the rule is an ingress rule."""
        if not self.direction:
            return False
        return self.direction.lower() == "ingress"

    def is_tcp(self) -> bool:
        """Check if the rule is TCP protocol."""
        # None means all protocols (including TCP) - treat as TCP-applicable
        if self.protocol is None:
            return True
        return self.protocol.lower() in ["tcp", "all"]

    def includes_port(self, port: int) -> bool:
        """Check if the rule includes a specific port."""
        if self.port_range_min is None or self.port_range_max is None:
            # If no port range specified, rule applies to all ports
            return True
        return self.port_range_min <= port <= self.port_range_max

    def get_ip_range_display(self) -> str:
        """
        Get a user-friendly display string for the IP range.

        Returns:
            str: Human-readable IP range description
        """
        if self.ip_range is None:
            return "anywhere (0.0.0.0/0, ::/0)"
        return self.ip_range

    def get_rule_display_name(self) -> str:
        """
        Get a user-friendly display name for the rule.

        Returns:
            str: Rule description if available, otherwise rule ID
        """
        if self.description:
            return f"'{self.description}' ({self.id})"
        return f"'{self.id}'"


class SecurityGroup(BaseModel):
    """
    Represents a StackIT IaaS Security Group.

    Attributes:
        id: The unique identifier of the security group
        name: The name of the security group
        project_id: The StackIT project ID containing the security group
        region: The region where the security group is located
        rules: List of security group rules
        in_use: Whether the security group is actively attached to any resources
    """

    id: str
    name: str
    project_id: str
    region: str = "eu01"
    rules: list[SecurityGroupRule] = []
    in_use: bool = False
