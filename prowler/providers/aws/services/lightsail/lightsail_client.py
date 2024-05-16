from prowler.providers.aws.services.lightsail.lightsail_service import Lightsail
from prowler.providers.common.common import get_global_provider

lightsail_client = Lightsail(get_global_provider())
