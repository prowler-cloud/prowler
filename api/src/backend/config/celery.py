import warnings

from celery import Celery, Task
from celery.signals import worker_process_init

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

celery_app.autodiscover_tasks(["api"])


@worker_process_init.connect
def _init_attack_paths_drivers(**_: object) -> None:
    """Initialize the attack-paths drivers in each forked worker.

    Runs after the Celery worker fork so each child owns its own Neo4j /
    Neptune driver with live IO threads. Prevents the fork-unsafety pattern
    that wedges gunicorn workers on ``pool.acquire`` — the Celery prefork
    pool has the same class of risk for any driver initialized in the parent.
    """
    from api.attack_paths import sink, staging

    # Staging is Neo4j-only, always needed on workers for cartography temp DBs.
    try:
        staging.init_driver()
    except Exception:  # pragma: no cover - defer to first-use failure semantics
        pass
    # Sink may be Neo4j or Neptune; fail loud if misconfigured so the worker
    # doesn't silently accept tasks it cannot fulfil.
    sink.init()


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
