from prowler.providers.common.provider import Provider
from prowler.providers.openstack.services.neutron.neutron_service import Neutron

neutron_client = Neutron(Provider.get_global_provider())
