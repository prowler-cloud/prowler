from prowler.providers.common.provider import Provider
from prowler.providers.fly.services.volume.volume_service import Volume

volume_client = Volume(Provider.get_global_provider())
