"""
Network scanning utilities for Prowler
Performs active port scanning on discovered public cloud resources

This module integrates nmap scanning capabilities into Prowler's workflow,
following the Luminaut pattern of post-scan enrichment rather than creating
separate checks.
"""

from typing import Any

try:
    import nmap3
    import nmap3.exceptions

    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

from prowler.lib.logger import logger


class NetworkScanner:
    """
    Active network scanner using nmap to identify open ports and services
    on publicly exposed cloud resources.

    This scanner performs targeted port scanning only on ports that are
    already identified as exposed through security group rules or firewall
    configurations, making it efficient and focused.
    """

    def __init__(self, timeout: int = 300):
        """
        Initialize the network scanner

        Args:
            timeout: Maximum time in seconds for each scan (default: 300)
        """
        self.timeout = timeout
        if not NMAP_AVAILABLE:
            logger.warning(
                "nmap3 library not installed. Install with: "
                "pip install 'prowler[network-scanning]'"
            )

    def scan_host(self, ip: str, ports: list[int] | None = None) -> dict:
        """
        Scan a single host on specified ports

        Args:
            ip: Target IP address to scan
            ports: List of ports to scan (if None, uses common web ports)

        Returns:
            Dictionary with scan results including:
            - ip: The scanned IP address
            - scanned_ports: List of ports that were scanned
            - open_services: List of discovered services
            - scan_successful: Boolean indicating scan success
        """
        if not NMAP_AVAILABLE:
            logger.error("nmap3 library not available")
            return {"error": "nmap3 not available", "scan_successful": False}

        # Use common ports if none specified
        if not ports:
            ports = [80, 443, 22, 3389, 8080, 8443, 3000, 5000]

        port_list = ",".join(str(p) for p in ports)
        logger.info(f"Scanning {ip} on ports: {port_list}")

        nmap = nmap3.Nmap()
        # --version-light: Faster service detection
        # -Pn: Skip host discovery (assume host is up)
        # -p: Specify ports
        nmap_args = "--version-light -Pn"

        if port_list:
            nmap_args += f" -p {port_list}"

        try:
            result = nmap.nmap_version_detection(
                target=ip,
                args=nmap_args,
                timeout=self.timeout,
            )

            # Parse results
            open_services = self._parse_nmap_results(result)

            logger.info(f"Nmap found {len(open_services)} services on {ip}")

            return {
                "ip": ip,
                "scanned_ports": ports,
                "open_services": open_services,
                "scan_successful": True,
            }

        except nmap3.exceptions.NmapNotInstalledError:
            logger.error(
                "nmap not found. Install nmap from: https://nmap.org/download.html"
            )
            return {
                "error": "nmap not installed",
                "scan_successful": False,
                "ip": ip,
            }

        except Exception as e:
            logger.error(f"Nmap scan failed for {ip}: {e}")
            return {"error": str(e), "scan_successful": False, "ip": ip}

    def _parse_nmap_results(self, nmap_result: dict) -> list[dict]:
        """
        Parse nmap3 results into simplified service list

        Args:
            nmap_result: Raw nmap3 scan results

        Returns:
            List of dictionaries containing service information
        """
        services = []
        supported_states = ["open", "closed", "unfiltered"]

        # Nmap results can have multiple keys, iterate through all
        for result_values in nmap_result.values():
            if "ports" in result_values:
                for port_info in result_values["ports"]:
                    if port_info.get("state") in supported_states:
                        service_info = port_info.get("service", {})
                        services.append(
                            {
                                "port": port_info.get("portid"),
                                "protocol": port_info.get("protocol", "tcp"),
                                "state": port_info.get("state"),
                                "service": service_info.get("name", "unknown"),
                                "product": service_info.get("product", ""),
                                "version": service_info.get("version", ""),
                            }
                        )

        return services


def extract_public_ips_and_ports(findings: list) -> dict[str, set[int]]:
    """
    Extract public IPs and their exposed ports from Prowler findings

    This function analyzes all findings to identify:
    1. Resources with public IP addresses
    2. Security group rules or firewall rules that expose ports to the internet
    3. The specific ports that are exposed

    Args:
        findings: List of all Prowler check findings

    Returns:
        Dict mapping IP addresses to sets of exposed port numbers
        Example: {"1.2.3.4": {80, 443, 22}, "5.6.7.8": {3306}}
    """
    ip_port_map = {}

    for finding in findings:
        # Skip findings that don't have resources
        if not hasattr(finding, "resource"):
            continue

        public_ip = None
        exposed_ports = set()

        # Extract public IP from various resource types
        if hasattr(finding.resource, "public_ip"):
            public_ip = finding.resource.public_ip

        # Extract exposed ports from security groups (AWS, OCI)
        if hasattr(finding.resource, "security_groups"):
            for sg in finding.resource.security_groups:
                if hasattr(sg, "ingress_rules"):
                    for rule in sg.ingress_rules:
                        if _is_public_rule(rule):
                            exposed_ports.update(_extract_ports_from_rule(rule))

        # Extract exposed ports from network security groups (Azure)
        if hasattr(finding.resource, "network_security_group"):
            nsg = finding.resource.network_security_group
            if hasattr(nsg, "security_rules"):
                for rule in nsg.security_rules:
                    if _is_public_rule(rule):
                        exposed_ports.update(_extract_ports_from_rule(rule))

        # Extract exposed ports from firewall rules (GCP)
        if hasattr(finding.resource, "firewall_rules"):
            for fw_rule in finding.resource.firewall_rules:
                if _is_public_firewall_rule(fw_rule):
                    exposed_ports.update(_extract_ports_from_firewall_rule(fw_rule))

        # Add to map if we found both IP and ports
        if public_ip and exposed_ports:
            if public_ip not in ip_port_map:
                ip_port_map[public_ip] = set()
            ip_port_map[public_ip].update(exposed_ports)

    return ip_port_map


def _is_public_rule(rule: Any) -> bool:
    """
    Check if security group rule allows public access (0.0.0.0/0 or ::/0)

    Args:
        rule: Security group rule object

    Returns:
        True if the rule allows access from the internet
    """
    # Check for IPv4 CIDR
    if hasattr(rule, "cidr_ipv4"):
        if rule.cidr_ipv4 in ["0.0.0.0/0"]:
            return True

    # Check for IPv6 CIDR
    if hasattr(rule, "cidr_ipv6"):
        if rule.cidr_ipv6 in ["::/0"]:
            return True

    # Azure format
    if hasattr(rule, "source_address_prefix"):
        if rule.source_address_prefix in ["*", "Internet", "0.0.0.0/0", "::/0"]:
            return True

    # Check if source CIDR blocks contain public access
    if hasattr(rule, "source"):
        source = rule.source
        if isinstance(source, str) and source in ["0.0.0.0/0", "::/0", "*"]:
            return True

    return False


def _is_public_firewall_rule(rule: Any) -> bool:
    """
    Check if GCP firewall rule allows public access

    Args:
        rule: GCP firewall rule object

    Returns:
        True if the rule allows access from the internet
    """
    if hasattr(rule, "source_ranges"):
        for source_range in rule.source_ranges:
            if source_range in ["0.0.0.0/0", "::/0"]:
                return True

    return False


def _extract_ports_from_rule(rule: Any) -> set[int]:
    """
    Extract port numbers from security group rule

    Args:
        rule: Security group rule object

    Returns:
        Set of port numbers exposed by this rule
    """
    ports = set()

    # AWS/OCI format
    if hasattr(rule, "from_port") and hasattr(rule, "to_port"):
        from_port = rule.from_port
        to_port = rule.to_port

        # Handle "all ports" case (-1 in AWS)
        if from_port == -1 or to_port == -1:
            # Return common ports instead of all 65535 ports
            return {80, 443, 22, 3389, 3306, 5432, 1433, 27017, 6379, 8080, 8443}

        # Handle None values
        if from_port is None or to_port is None:
            return {80, 443, 22, 3389, 8080}

        # Add port range (limit to prevent scanning too many ports)
        port_range = to_port - from_port + 1
        if port_range > 100:
            # If range is too large, just use common ports
            return {80, 443, 22, 3389, 8080, 8443}

        for port in range(from_port, to_port + 1):
            ports.add(port)

    # Azure format
    if hasattr(rule, "destination_port_range"):
        port_range = rule.destination_port_range
        if port_range == "*":
            return {80, 443, 22, 3389, 8080, 8443}
        elif "-" in str(port_range):
            start, end = str(port_range).split("-")
            try:
                for port in range(int(start), int(end) + 1):
                    ports.add(port)
            except ValueError:
                pass
        else:
            try:
                ports.add(int(port_range))
            except ValueError:
                pass

    return ports


def _extract_ports_from_firewall_rule(rule: Any) -> set[int]:
    """
    Extract port numbers from GCP firewall rule

    Args:
        rule: GCP firewall rule object

    Returns:
        Set of port numbers exposed by this rule
    """
    ports = set()

    if hasattr(rule, "allowed"):
        for allowed in rule.allowed:
            if hasattr(allowed, "ports"):
                for port_spec in allowed.ports:
                    if "-" in str(port_spec):
                        # Port range
                        start, end = str(port_spec).split("-")
                        try:
                            for port in range(int(start), int(end) + 1):
                                ports.add(port)
                        except ValueError:
                            pass
                    else:
                        # Single port
                        try:
                            ports.add(int(port_spec))
                        except ValueError:
                            pass

    return ports
