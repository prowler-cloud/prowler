import json
from datetime import datetime

from prowler.lib.check.models import Check, Check_Report
from prowler.providers.ionos.lib.service import IonosService
from prowler.providers.ionos.services.server.server_client import ionos_server_client


class server_public_ip(Check):
    def execute(self):
        findings = []
        
        # Get all servers
        servers = ionos_server_client.servers
        
        for server in servers:
            report = Check_Report(self.metadata())
            report.resource_id = server.id
            report.resource_name = server.properties.name if hasattr(server.properties, 'name') else "No Name"
            
            # Check if server has public IP addresses
            has_public_ip = False
            public_ips = []
            
            if hasattr(server, 'entities') and hasattr(server.entities, 'nics'):
                for nic in server.entities.nics.items:
                    if hasattr(nic.properties, 'ips'):
                        for ip in nic.properties.ips:
                            # Simple check for non-private IP ranges
                            if not (ip.startswith('10.') or 
                                    ip.startswith('172.16.') or
                                    ip.startswith('192.168.') or
                                    ip.startswith('169.254.')):
                                has_public_ip = True
                                public_ips.append(ip)
            
            if has_public_ip:
                report.status = "FAIL"
                report.status_extended = f"Server {report.resource_name} (ID: {report.resource_id}) has public IP address(es): {', '.join(public_ips)}"
            else:
                report.status = "PASS"
                report.status_extended = f"Server {report.resource_name} (ID: {report.resource_id}) does not have any public IP addresses"
            
            # Include server details in the report
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