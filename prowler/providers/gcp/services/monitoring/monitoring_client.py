from prowler.providers.common.common import global_provider
from prowler.providers.gcp.services.monitoring.monitoring_service import Monitoring

monitoring_client = Monitoring(global_provider)
