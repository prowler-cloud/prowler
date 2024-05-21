from prowler.providers.aws.services.dynamodb.dynamodb_service import DynamoDB
from prowler.providers.common.provider import Provider

dynamodb_client = DynamoDB(Provider.get_global_provider())
