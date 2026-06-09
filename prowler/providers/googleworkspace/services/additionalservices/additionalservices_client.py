from prowler.providers.common.provider import Provider
from prowler.providers.googleworkspace.services.additionalservices.additionalservices_service import (
    AdditionalServices,
)

additionalservices_client = AdditionalServices(Provider.get_global_provider())
