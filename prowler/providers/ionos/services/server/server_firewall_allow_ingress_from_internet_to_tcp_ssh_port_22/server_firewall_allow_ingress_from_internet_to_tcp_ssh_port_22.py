import json
from prowler.lib.check.models import Check, Check_Report_IONOS
from prowler.providers.ionos.lib.service import IonosService
from prowler.providers.ionos.services.server.server_client import ionos_server_client
from prowler.lib.logger import logger

class server_firewall_allow_ingress_from_internet_to_tcp_ssh_port_22(
    Check
):
    def execute(self):
        findings = []
        servers_response = ionos_server_client.servers
        servers = servers_response.items if hasattr(servers_response, 'items') else []
        
        for server in servers:
            nics = ionos_server_client.get_nics_for_server(server.id)
            report = Check_Report_IONOS(self.metadata(), resource=server)
            report.resource_id = server.id
            report.resource_name = server.properties.name if hasattr(server.properties, 'name') else "No Name"
            
            has_open_ssh = False
            for nic in nics:
                rules = ionos_server_client.get_network_security_rules(server.id, nic.id)
                if not rules:
                    continue
                
                for rule in rules:
                    logger.debug(f"Checking rule: {rule}")
                    if (
                        rule.properties.protocol == "TCP"
                        and rule.properties.port_range_start <= 22 
                        and rule.properties.port_range_end >= 22
                        and (rule.properties.source_ip == "0.0.0.0/0" or rule.properties.source_ip == None)
                    ):
                        has_open_ssh = True
                        break
                
                if has_open_ssh:
                    break
                    
            if has_open_ssh:
                report.status = "FAIL"
                report.status_extended = (
                    f"Server {server.properties.name} has firewall rules with SSH port 22 open to the internet"
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Server {server.properties.name} does not have SSH port 22 open to the internet"
                )
            
            server_details = {
                "id": server.id,
                "name": report.resource_name,
                "datacenter_id": server.datacenter_id if hasattr(server, 'datacenter_id') else "N/A",
                "has_public_ip": False,
                "public_ips": []
            }
            report.resource_details = json.dumps(server_details)
            findings.append(report)

        return findings