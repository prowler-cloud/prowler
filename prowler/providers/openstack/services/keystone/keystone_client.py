from prowler.providers.common.provider import Provider
from prowler.providers.openstack.services.keystone.keystone_service import Keystone

keystone_client = Keystone(Provider.get_global_provider())
