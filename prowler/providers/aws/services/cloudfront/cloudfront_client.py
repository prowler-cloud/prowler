from prowler.providers.aws.services.cloudfront.cloudfront_service import CloudFront
from prowler.providers.common.provider import Provider

cloudfront_client = CloudFront(Provider.get_global_provider())
