from prowler.providers.aws.services.shield.shield_service import Shield
from prowler.providers.common.common import get_global_provider

shield_client = Shield(get_global_provider())
