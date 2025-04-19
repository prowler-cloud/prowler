from prowler.providers.opennebula.services.acc.acc_service import ACCService
from prowler.providers.common.provider import Provider

acc_client = ACCService(Provider.get_global_provider())