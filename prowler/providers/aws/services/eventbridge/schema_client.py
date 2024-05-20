from prowler.providers.aws.services.eventbridge.eventbridge_service import Schema
from prowler.providers.common.provider import Provider

schema_client = Schema(Provider.get_global_provider())
