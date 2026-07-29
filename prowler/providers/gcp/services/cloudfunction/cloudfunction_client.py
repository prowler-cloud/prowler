from prowler.providers.common.provider import Provider
from prowler.providers.gcp.services.cloudfunction.cloudfunction_service import (
    CloudFunction,
)

cloudfunction_client = CloudFunction(Provider.get_global_provider())
