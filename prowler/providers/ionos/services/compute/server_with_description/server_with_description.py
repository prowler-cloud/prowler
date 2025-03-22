import json
from datetime import datetime

from prowler.lib.check.models import Check, Check_Report
from prowler.providers.ionos.lib.service import IonosService


class server_with_description(Check):
    def execute(self):
        findings = []
        
        # Obtener el servicio de compute a través del proveedor
        compute_client = self.provider.get_compute()
        
        # Obtener todos los servidores
        servers = compute_client.get_servers()
        
        # Verificar cada servidor para determinar si tiene una descripción
        for server in servers:
            report = Check_Report(self.metadata())
            report.resource_id = server.id
            report.resource_name = server.properties.name if hasattr(server.properties, 'name') else "No Name"
            
            # Verificar si el servidor tiene una descripción definida y no está vacía
            has_description = (
                hasattr(server.properties, 'description') and 
                server.properties.description is not None and 
                server.properties.description.strip() != ""
            )
            
            if has_description:
                report.status = "PASS"
                report.status_extended = f"El servidor {report.resource_name} (ID: {report.resource_id}) tiene una descripción definida."
            else:
                report.status = "FAIL"
                report.status_extended = f"El servidor {report.resource_name} (ID: {report.resource_id}) no tiene una descripción definida."
            
            # Recopilar detalles adicionales del servidor
            server_details = {
                "id": server.id,
                "name": report.resource_name,
                "datacenter_id": getattr(server, 'datacenter_id', "N/A"),
                "creation_date": getattr(server.metadata, 'created_date', datetime.now().isoformat()) if hasattr(server, 'metadata') else "N/A",
                "state": getattr(server.properties, 'vm_state', "N/A") if hasattr(server.properties, 'vm_state') else "N/A",
            }
            
            report.resource_details = json.dumps(server_details)
            findings.append(report)
            
        return findings

