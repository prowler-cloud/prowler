from prowler.providers.aws.services.s3.s3_service import S3
from prowler.providers.common.provider import Provider

s3_client = S3(Provider.get_global_provider())
