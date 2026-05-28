from prowler.providers.common.provider import Provider
from prowler.providers.linode.services.instance.instance_service import InstanceService

instance_client = InstanceService(Provider.get_global_provider())
