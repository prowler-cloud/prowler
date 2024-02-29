from prowler.providers.azure.services.monitor.monitor_service import Monitor
from prowler.providers.common.common import get_global_provider

monitor_client = Monitor(get_global_provider())
