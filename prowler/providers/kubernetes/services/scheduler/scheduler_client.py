from prowler.providers.common.common import get_global_provider
from prowler.providers.kubernetes.services.scheduler.scheduler_service import Scheduler

scheduler_client = Scheduler(get_global_provider())
