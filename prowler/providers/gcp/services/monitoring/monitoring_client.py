from prowler.providers.common.provider import Provider
from prowler.providers.gcp.services.monitoring.monitoring_service import Monitoring

monitoring_client = Monitoring(Provider.get_global_provider())
