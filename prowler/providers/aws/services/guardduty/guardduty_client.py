from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty
from prowler.providers.common.common import get_global_provider

guardduty_client = GuardDuty(get_global_provider())
