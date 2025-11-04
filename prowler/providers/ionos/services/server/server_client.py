from prowler.providers.common.provider import Provider
from prowler.providers.ionos.services.server.server_service import IonosServer

ionos_server_client = IonosServer(Provider.get_global_provider())
