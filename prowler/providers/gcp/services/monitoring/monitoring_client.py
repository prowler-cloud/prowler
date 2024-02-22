from prowler.providers.common.common import get_global_provider
from prowler.providers.gcp.services.monitoring.monitoring_service import Monitoring

monitoring_client = Monitoring(get_global_provider())
