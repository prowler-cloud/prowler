from prowler.providers.aws.services.shield.shield_service import Shield
from prowler.providers.common.provider import Provider

shield_client = Shield(Provider.get_global_provider())
