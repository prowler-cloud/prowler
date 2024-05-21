from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty
from prowler.providers.common.provider import Provider

guardduty_client = GuardDuty(Provider.get_global_provider())
