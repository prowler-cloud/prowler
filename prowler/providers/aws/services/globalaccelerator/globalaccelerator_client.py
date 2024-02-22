from prowler.providers.aws.services.globalaccelerator.globalaccelerator_service import (
    GlobalAccelerator,
)
from prowler.providers.common.common import get_global_provider

globalaccelerator_client = GlobalAccelerator(get_global_provider())
