from prowler.providers.common.provider import Provider
from prowler.providers.linode.services.administration.administration_service import (
    AdministrationService,
)

administration_client = AdministrationService(Provider.get_global_provider())
