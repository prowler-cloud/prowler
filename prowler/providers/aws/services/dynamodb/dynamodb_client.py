from prowler.providers.aws.services.dynamodb.dynamodb_service import DynamoDB
from prowler.providers.common.common import get_global_provider

dynamodb_client = DynamoDB(get_global_provider())
