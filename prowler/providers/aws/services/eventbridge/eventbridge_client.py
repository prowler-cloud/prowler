from prowler.providers.aws.services.eventbridge.eventbridge_service import EventBridge
from prowler.providers.common.provider import Provider

eventbridge_client = EventBridge(Provider.get_global_provider())
