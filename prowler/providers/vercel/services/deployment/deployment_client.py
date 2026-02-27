from prowler.providers.common.provider import Provider
from prowler.providers.vercel.services.deployment.deployment_service import Deployment

deployment_client = Deployment(Provider.get_global_provider())
