from prowler.providers.common.common import global_provider
from prowler.providers.kubernetes.services.scheduler.scheduler_service import Scheduler

scheduler_client = Scheduler(global_provider)
