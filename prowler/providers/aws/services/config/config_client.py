from prowler.providers.aws.services.config.config_service import Config
from prowler.providers.common.provider import Provider

config_client = Config(Provider.get_global_provider())
