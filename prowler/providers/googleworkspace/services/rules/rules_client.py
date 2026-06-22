from prowler.providers.common.provider import Provider
from prowler.providers.googleworkspace.services.rules.rules_service import (
    Rules,
)

rules_client = Rules(Provider.get_global_provider())
