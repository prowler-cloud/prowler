from prowler.providers.aws.services.route53.route53_service import Route53
from prowler.providers.common.provider import Provider

route53_client = Route53(Provider.get_global_provider())
