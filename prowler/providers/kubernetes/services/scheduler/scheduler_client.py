from prowler.providers.common.provider import Provider
from prowler.providers.kubernetes.services.scheduler.scheduler_service import Scheduler

scheduler_client = Scheduler(Provider.get_global_provider())
