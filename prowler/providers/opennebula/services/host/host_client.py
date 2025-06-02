from prowler.providers.opennebula.services.host.host_service import HostService
from prowler.providers.common.provider import Provider

host_client = HostService(Provider.get_global_provider())