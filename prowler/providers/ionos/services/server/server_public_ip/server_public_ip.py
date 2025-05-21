import json
import ipaddress
from datetime import datetime

from prowler.lib.check.models import Check, Check_Report_IONOS
from prowler.providers.ionos.lib.service import IonosService
from prowler.providers.ionos.services.server.server_client import ionos_server_client
from prowler.lib.logger import logger

class server_public_ip(Check):
    def execute(self):
        findings = []
        
        servers_response = ionos_server_client.servers
        
        servers = servers_response.items if hasattr(servers_response, 'items') else []
        
        for server in servers:
            logger.info("Checking server: %s", server.id)
            report = Check_Report_IONOS(self.metadata())
            report.resource_id = server.id
            report.resource_name = server.properties.name if hasattr(server.properties, 'name') else "No Name"
            
            has_public_ip = False
            public_ips = []
            
            nics = ionos_server_client.get_nics_for_server(server.id)

            for nic in nics:                
                if nic.properties.ips:
                    for ip in nic.properties.ips:
                        try:
                            ip_obj = ipaddress.ip_address(ip)
                            if ip_obj.is_global:
                                has_public_ip = True
                                public_ips.append(ip)
                        except ValueError:
                            continue
            
            if has_public_ip:
                report.status = "FAIL"
                report.status_extended = (
                    f"Server {report.resource_name} (ID: {report.resource_id}) "
                    f"has public IP address(es): {', '.join(public_ips)}"
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Server {report.resource_name} (ID: {report.resource_id}) does not have any public IP addresses"
                )
            
            server_details = {
                "id": server.id,
                "name": report.resource_name,
                "datacenter_id": server.datacenter_id if hasattr(server, 'datacenter_id') else "N/A",
                "has_public_ip": has_public_ip,
                "public_ips": public_ips if has_public_ip else []
            }
            report.resource_details = json.dumps(server_details)
            findings.append(report)
            
        return findings
