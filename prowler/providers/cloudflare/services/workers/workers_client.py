from prowler.providers.cloudflare.services.workers.workers_service import Workers
from prowler.providers.common.provider import Provider

workers_client = Workers(Provider.get_global_provider())
