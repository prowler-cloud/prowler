from prowler.providers.aws.services.eventbridge.eventbridge_service import EventBridge
from prowler.providers.common.common import get_global_provider

eventbridge_client = EventBridge(get_global_provider())
