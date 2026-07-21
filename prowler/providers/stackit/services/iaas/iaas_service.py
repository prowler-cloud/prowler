from typing import Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.stackit.stackit_provider import StackitProvider, suppress_stderr


class IaaSService:
    """
    StackIT IaaS Service class to handle security group operations.

    This service uses the StackIT Python SDK to access IaaS resources.
    Authentication is delegated to the SDK, which signs the RSA challenge
    in the configured service account key and refreshes access tokens
    internally for the life of the scan.
    """

    def __init__(self, provider: StackitProvider):
        """
        Initialize the IaaS service.

        Args:
            provider: The StackIT provider instance
        """
        self.provider = provider
        self.project_id = provider.identity.project_id
        self.service_account_key_path = provider.session.get("service_account_key_path")
        self.scan_unused_services = provider.scan_unused_services

        # Generate regional clients (AWS pattern)
        self.regional_clients = provider.generate_regional_clients("iaas")
        self.audited_regions = provider.identity.audited_regions

        # Initialize security groups list
        self.security_groups: list[SecurityGroup] = []

        # Initialize server NICs list and used security group IDs
        self.server_nics: list = []
        self.in_use_sg_ids: set[str] = set()

        # Initialize server list and supporting indices
        self.servers: list[Server] = []
        self._nic_device_index: dict[str, str] = {}  # nic_id → server_id
        self._public_ip_server_ids: set[str] = set()

        # Fetch resources from all regions
        self._fetch_all_regions()
        self._log_skipped_security_groups()

    def _log_skipped_security_groups(self):
        """Explain an empty report when every security group is skipped.

        Following the same convention as the rest of Prowler, security group
        checks only evaluate groups that are in use (attached to a network
        interface) unless ``--scan-unused-services`` is set. When a project
        has security groups but none are attached, every check returns no
        finding, which looks like "nothing was scanned". Emit an explicit
        hint so the empty report is not mistaken for a failure.
        """
        if (
            not self.scan_unused_services
            and self.security_groups
            and not any(sg.in_use for sg in self.security_groups)
        ):
            logger.info(
                f"{len(self.security_groups)} StackIT security group(s) were "
                f"found but none are attached to a network interface, so all "
                f"of them are skipped and no finding is produced. Re-run with "
                f"--scan-unused-services to audit security groups that are "
                f"not currently in use."
            )

    def _fetch_all_regions(self):
        """Fetch resources from all audited regions.

        A project is not necessarily provisioned in every StackIT region. A
        region where the project does not exist answers the IaaS endpoints
        with HTTP 404 (``resource not found: project``). That is expected, so
        the region is skipped and the scan continues with the remaining
        regions instead of aborting (which previously left every check
        failing to load and produced an empty, misleading report).

        Credential and permission failures (401/403) still propagate via
        ``handle_api_error`` so a misconfigured account fails loudly.
        """
        for region, client in self.regional_clients.items():
            try:
                self._list_server_nics(client, region)
                self._list_security_groups(client, region)
                self._list_public_ips(client, region)
                self._list_servers(client, region)
            except Exception as error:
                if getattr(error, "status", None) == 404:
                    logger.info(
                        f"StackIT project {self.project_id} has no IaaS "
                        f"presence in region {region} (404 resource not "
                        f"found); skipping this region."
                    )
                    continue
                raise

    @staticmethod
    def _extract_items(response, endpoint_name: str) -> list:
        """Extract the items list from a StackIT SDK response.

        Handles three response shapes safely:
            - SDK model exposing an ``items`` attribute (not the ``dict.items`` method)
            - Raw ``dict`` with an ``"items"`` key
            - Plain ``list``

        ``isinstance(response, dict)`` is checked first because ``dict`` has an
        ``items`` *method*; ``hasattr(response, "items")`` is otherwise True for
        plain dicts and silently returns the bound method.
        """
        if isinstance(response, dict):
            return response.get("items", [])
        if isinstance(response, list):
            return response
        items_attr = getattr(response, "items", None)
        if items_attr is not None and not callable(items_attr):
            return items_attr
        logger.warning(
            f"Unexpected response type from {endpoint_name}: {type(response)}"
        )
        return []

    @staticmethod
    def _get_item_field(item, *keys, default=None):
        """Read a field from an SDK model (attribute) or a raw ``dict`` (key).

        ``_extract_items`` already yields either SDK models or raw dicts, so the
        correlation logic must read fields from both shapes. Multiple key aliases
        are accepted so snake_case SDK attributes and camelCase API/dict keys are
        both supported (e.g. ``network_interface`` / ``networkInterface``).
        Returns the first non-None match, otherwise ``default``.
        """
        if isinstance(item, dict):
            for key in keys:
                value = item.get(key)
                if value is not None:
                    return value
            return default
        for key in keys:
            value = getattr(item, key, None)
            if value is not None:
                return value
        return default

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
            # Suppress StackIT SDK stderr messages during API calls
            with suppress_stderr():
                return api_function(*args, **kwargs)
        except Exception as e:
            # Use centralized error handler from provider
            self.provider.handle_api_error(e)
            raise

    def _list_security_groups(self, client, region: str):
        """
        List all security groups in the StackIT project and fetch their rules.

        This method populates the self.security_groups list with SecurityGroup
        objects containing information about each security group and its rules.
        """
        if not client:
            logger.warning(
                f"Cannot list security groups in {region}: StackIT IaaS client not available"
            )
            return

        # Call the list security groups API with centralized error handling
        response = self._handle_api_call(
            client.list_security_groups, project_id=self.project_id, region=region
        )

        # Extract security groups from response
        security_groups_list = self._extract_items(response, "list_security_groups")

        # Process each security group
        for sg_data in security_groups_list:
            try:
                # Extract security group information
                if hasattr(sg_data, "id"):
                    sg_id = sg_data.id
                    sg_name = getattr(sg_data, "name", sg_id)
                elif isinstance(sg_data, dict):
                    sg_id = sg_data.get("id", "")
                    sg_name = sg_data.get("name", sg_id)
                else:
                    logger.warning(
                        f"Unexpected security group data type: {type(sg_data)}"
                    )
                    continue

            except Exception as e:
                logger.error(f"Error processing security group: {e}")
                continue

            # Get security group rules after local parsing succeeds so API errors
            # from the rules endpoint propagate instead of being downgraded.
            rules = self._list_security_group_rules(client, region, sg_id)

            security_group = SecurityGroup(
                id=sg_id,
                name=sg_name,
                project_id=self.project_id,
                region=region,
                rules=rules,
                # in_use_sg_ids is normalized to str; the SDK returns the NIC
                # security group references as uuid.UUID while the security
                # group id is a str, so compare on the string form.
                in_use=str(sg_id) in self.in_use_sg_ids,
            )
            self.security_groups.append(security_group)

        logger.info(
            f"Successfully listed {len(security_groups_list)} security groups in {region}"
        )

    def _list_security_group_rules(
        self, client, region: str, security_group_id: str
    ) -> list["SecurityGroupRule"]:
        """
        List all rules for a specific security group.

        Args:
            client: The StackIT IaaS client
            region: The region of the security group
            security_group_id: The ID of the security group

        Returns:
            list: List of SecurityGroupRule objects
        """
        rules = []
        # Get security group rules via SDK
        response = self._handle_api_call(
            client.list_security_group_rules,
            project_id=self.project_id,
            region=region,
            security_group_id=security_group_id,
        )

        # Extract rules from response
        rules_list = self._extract_items(response, "list_security_group_rules")

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

        return rules

    def _list_server_nics(self, client, region: str):
        """
        List all server network interfaces (NICs) in the StackIT project.

        This method fetches all NICs and determines which security groups are
        actively in use by checking which security groups are attached to any NIC.
        """
        if not client:
            logger.warning(
                f"Cannot list server NICs in {region}: StackIT IaaS client not available"
            )
            return

        # Call the list project NICs API with centralized error handling
        response = self._handle_api_call(
            client.list_project_nics, project_id=self.project_id, region=region
        )

        # Extract NICs from response
        nics_list = self._extract_items(response, "list_project_nics")

        self.server_nics.extend(nics_list)

        # A security group is "in use" when attached to any NIC
        used_sg_ids = self._get_used_security_group_ids(nics_list)
        self.in_use_sg_ids.update(used_sg_ids)

        # Build nic_id → server_id index for public IP cross-reference
        for nic in nics_list:
            try:
                nic_id = str(self._get_item_field(nic, "id") or "")
                device = self._get_item_field(nic, "device")
                if nic_id and device:
                    self._nic_device_index[nic_id] = str(device)
            except Exception as e:
                logger.debug(f"Error indexing NIC device: {e}")
                continue

        logger.info(
            f"Successfully listed {len(nics_list)} NICs in {region}. "
            f"Found {len(used_sg_ids)} security groups attached to NICs."
        )

    def _list_public_ips(self, client, region: str):
        """
        List all public IPs in the project and record which servers have one attached.

        A public IP is considered attached to a server when its ``network_interface``
        field (a NIC UUID) matches a NIC whose ``device`` field points to a server.
        The result is stored in ``self._public_ip_server_ids`` so that
        ``_list_servers`` can set ``has_public_ip`` when creating Server objects.
        """
        if not client:
            logger.warning(
                f"Cannot list public IPs in {region}: StackIT IaaS client not available"
            )
            return

        response = self._handle_api_call(
            client.list_public_ips, project_id=self.project_id, region=region
        )
        ips_list = self._extract_items(response, "list_public_ips")

        for ip_data in ips_list:
            try:
                network_interface = self._get_item_field(
                    ip_data, "network_interface", "networkInterface"
                )
                if network_interface is None:
                    continue
                server_id = self._nic_device_index.get(str(network_interface))
                if server_id:
                    self._public_ip_server_ids.add(server_id)
            except Exception as e:
                logger.debug(f"Error processing public IP: {e}")
                continue

        logger.info(f"Successfully listed {len(ips_list)} public IPs in {region}")

    def _list_servers(self, client, region: str):
        """
        List all servers in the project and populate ``self.servers``.

        ``has_public_ip`` is set to True for any server whose ID appears in
        ``self._public_ip_server_ids`` (populated by ``_list_public_ips``).
        """
        if not client:
            logger.warning(
                f"Cannot list servers in {region}: StackIT IaaS client not available"
            )
            return

        response = self._handle_api_call(
            client.list_servers, project_id=self.project_id, region=region
        )
        servers_list = self._extract_items(response, "list_servers")

        for server_data in servers_list:
            try:
                server_id = str(self._get_item_field(server_data, "id") or "")
                server_name = self._get_item_field(server_data, "name") or server_id
                server = Server(
                    id=server_id,
                    name=server_name,
                    project_id=self.project_id,
                    region=region,
                    has_public_ip=server_id in self._public_ip_server_ids,
                )
                self.servers.append(server)
            except Exception as e:
                logger.error(f"Error processing server: {e}")
                continue

        logger.info(f"Successfully listed {len(servers_list)} servers in {region}")

    def _get_used_security_group_ids(self, nics_list) -> set[str]:
        """
        Get the set of security group IDs that are actively attached to any NIC.

        Returns:
            set[str]: Set of security group IDs that are attached to at least one NIC
        """
        used_sg_ids = set()

        for nic in nics_list:
            try:
                # Extract security groups from NIC. The SDK model exposes them
                # as ``security_groups``; a raw dict uses the camelCase
                # ``securityGroups`` key (falling back to snake_case).
                if hasattr(nic, "security_groups"):
                    sg_list = nic.security_groups
                elif isinstance(nic, dict):
                    sg_list = nic.get("securityGroups", nic.get("security_groups", []))
                else:
                    continue

                if sg_list:
                    for sg_id in sg_list:
                        if sg_id:
                            # The SDK returns these references as uuid.UUID
                            # while the security group id is a str; normalize
                            # to str so the membership test in
                            # _list_security_groups matches.
                            used_sg_ids.add(str(sg_id))

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
            return f"{self.description} ({self.id})"
        return f"{self.id}"


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
    region: str
    rules: list[SecurityGroupRule] = []
    in_use: bool = False


class Server(BaseModel):
    """
    Represents a StackIT IaaS Server.

    Attributes:
        id: The unique identifier of the server
        name: The name of the server
        project_id: The StackIT project ID containing the server
        region: The region where the server is located
        has_public_ip: Whether a public IP is directly attached to any of the server's NICs
    """

    id: str
    name: str
    project_id: str
    region: str
    has_public_ip: bool = False
