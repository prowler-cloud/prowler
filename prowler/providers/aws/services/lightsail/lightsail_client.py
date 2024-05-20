from prowler.providers.aws.services.lightsail.lightsail_service import Lightsail
from prowler.providers.common.provider import Provider

lightsail_client = Lightsail(Provider.get_global_provider())
