import warnings

from celery import Celery, Task

from config.env import env

# Suppress specific warnings from django-rest-auth: https://github.com/iMerica/dj-rest-auth/issues/684
warnings.filterwarnings(
    "ignore", category=UserWarning, module="dj_rest_auth.registration.serializers"
)

BROKER_VISIBILITY_TIMEOUT = env.int("DJANGO_BROKER_VISIBILITY_TIMEOUT", default=86400)

celery_app = Celery("tasks")

celery_app.config_from_object("django.conf:settings", namespace="CELERY")
celery_app.conf.update(result_extended=True, result_expires=None)

celery_app.conf.broker_transport_options = {
    "visibility_timeout": BROKER_VISIBILITY_TIMEOUT,
    "queue_order_strategy": "priority",
}
celery_app.conf.task_default_priority = 6
celery_app.conf.result_backend_transport_options = {
    "visibility_timeout": BROKER_VISIBILITY_TIMEOUT
}
celery_app.conf.visibility_timeout = BROKER_VISIBILITY_TIMEOUT

# Durable delivery: keep the message until the task finishes, so a worker killed
# mid-task (deploy/OOM/eviction) does not silently drop it. Reserve one task at a
# time so a crash exposes at most one extra reserved message.
celery_app.conf.task_acks_late = True
celery_app.conf.task_reject_on_worker_lost = True
celery_app.conf.worker_prefetch_multiplier = env.int(
    "DJANGO_CELERY_WORKER_PREFETCH_MULTIPLIER", default=1
)
# On SIGTERM, give the worker time to finish or re-queue in-flight tasks before
# it is forcefully killed (Celery 5.5+ soft shutdown).
celery_app.conf.worker_soft_shutdown_timeout = env.int(
    "DJANGO_CELERY_WORKER_SOFT_SHUTDOWN_TIMEOUT", default=60
)
# Bound execution so a blocked task cannot pin a worker forever. Connection
# checks get a tight limit; scans and provider/tenant deletions can legitimately
# run for more than a day on large tenants, so they get a much higher cap;
# everything else a generous default.
_TASK_HARD_LIMIT = env.int("DJANGO_CELERY_TASK_TIME_LIMIT", default=6 * 60 * 60)
_TASK_SOFT_LIMIT = env.int(
    "DJANGO_CELERY_TASK_SOFT_TIME_LIMIT", default=_TASK_HARD_LIMIT - 600
)
_LONG_TASK_HARD_LIMIT = env.int(
    "DJANGO_CELERY_LONG_TASK_TIME_LIMIT", default=48 * 60 * 60
)
_LONG_TASK_SOFT_LIMIT = env.int(
    "DJANGO_CELERY_LONG_TASK_SOFT_TIME_LIMIT", default=_LONG_TASK_HARD_LIMIT - 600
)
celery_app.conf.task_annotations = {
    "*": {"soft_time_limit": _TASK_SOFT_LIMIT, "time_limit": _TASK_HARD_LIMIT},
    **{
        name: {"soft_time_limit": 60, "time_limit": 120}
        for name in (
            "provider-connection-check",
            "integration-connection-check",
            "lighthouse-connection-check",
            "lighthouse-provider-connection-check",
        )
    },
    **{
        name: {
            "soft_time_limit": _LONG_TASK_SOFT_LIMIT,
            "time_limit": _LONG_TASK_HARD_LIMIT,
        }
        for name in (
            "scan-perform",
            "scan-perform-scheduled",
            "provider-deletion",
            "tenant-deletion",
        )
    },
}

celery_app.autodiscover_tasks(["api"])


class RLSTask(Task):
    def apply_async(
        self,
        args=None,
        kwargs=None,
        task_id=None,
        producer=None,
        link=None,
        link_error=None,
        shadow=None,
        **options,
    ):
        from django_celery_results.models import TaskResult

        from api.models import Task as APITask

        result = super().apply_async(
            args=args,
            kwargs=kwargs,
            task_id=task_id,
            producer=producer,
            link=link,
            link_error=link_error,
            shadow=shadow,
            **options,
        )
        task_result_instance = TaskResult.objects.get(task_id=result.task_id)
        from api.db_utils import rls_transaction

        tenant_id = kwargs.get("tenant_id")
        with rls_transaction(tenant_id):
            APITask.objects.update_or_create(
                id=task_result_instance.task_id,
                tenant_id=tenant_id,
                defaults={"task_runner_task": task_result_instance},
            )
        return result
