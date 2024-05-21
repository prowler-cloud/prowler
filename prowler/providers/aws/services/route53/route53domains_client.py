from prowler.providers.aws.services.route53.route53_service import Route53Domains
from prowler.providers.common.provider import Provider

route53domains_client = Route53Domains(Provider.get_global_provider())
