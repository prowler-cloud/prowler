from prowler.providers.aws.services.globalaccelerator.globalaccelerator_service import (
    GlobalAccelerator,
)
from prowler.providers.common.provider import Provider

globalaccelerator_client = GlobalAccelerator(Provider.get_global_provider())
