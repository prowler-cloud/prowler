from prowler.providers.aws.services.dynamodb.dynamodb_service import DAX
from prowler.providers.common.provider import Provider

dax_client = DAX(Provider.get_global_provider())
