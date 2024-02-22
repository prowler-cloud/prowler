from prowler.providers.aws.services.config.config_service import Config
from prowler.providers.common.common import get_global_provider

config_client = Config(get_global_provider())
