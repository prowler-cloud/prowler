import ipaddress
import json
from typing import Iterable, List

from prowler.lib.check.models import Check, Check_Report_IONOS
from prowler.lib.logger import logger
from prowler.providers.ionos.services.server.server_client import ionos_server_client


class server_public_ip(Check):
    def execute(self):
        findings = []
        servers: Iterable = getattr(
            ionos_server_client.servers, "items", ionos_server_client.servers
        )

        for server in servers or []:
            logger.info("Checking server: %s", server.id)
            report = Check_Report_IONOS(self.metadata(), resource=server)
            report.resource_id = server.id
            report.resource_name = getattr(server.properties, "name", "No Name")

            public_ips: List[str] = []
            for nic in ionos_server_client.get_nics_for_server(server.id) or []:
                for ip in getattr(nic.properties, "ips", []) or []:
                    try:
                        if ipaddress.ip_address(ip).is_global:
                            public_ips.append(ip)
                    except ValueError:
                        logger.debug(
                            "Skipping invalid IP address %s for server %s",
                            ip,
                            server.id,
                        )

            has_public_ip = bool(public_ips)

            if has_public_ip:
                joined_ips = ", ".join(public_ips)
                report.status = "FAIL"
                report.status_extended = f"Server {report.resource_name} (ID: {report.resource_id}) has public IP address(es): {joined_ips}"
            else:
                report.status = "PASS"
                report.status_extended = f"Server {report.resource_name} (ID: {report.resource_id}) does not have any public IP addresses"

            server_details = {
                "id": server.id,
                "name": report.resource_name,
                "datacenter_id": getattr(server, "datacenter_id", "N/A"),
                "has_public_ip": has_public_ip,
                "public_ips": public_ips,
            }
            report.resource_details = json.dumps(server_details)
            findings.append(report)

        return findings
