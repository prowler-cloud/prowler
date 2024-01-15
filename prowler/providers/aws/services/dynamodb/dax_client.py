from prowler.providers.aws.services.dynamodb.dynamodb_service import DAX
from prowler.providers.common.common import get_global_provider

dax_client = DAX(get_global_provider())
