from prowler.providers.ionos.services.server.server_service import IonosServer
from prowler.providers.common.provider import Provider

print("este es el proveedor: " + Provider.get_global_provider().type)
ionos_server_client = IonosServer(Provider.get_global_provider())