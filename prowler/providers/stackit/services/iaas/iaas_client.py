from prowler.providers.common.provider import Provider
from prowler.providers.stackit.services.iaas.iaas_service import IaaSService

iaas_client = IaaSService(Provider.get_global_provider())
