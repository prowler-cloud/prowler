from celery import Celery, Task
from config.env import env

BROKER_VISIBILITY_TIMEOUT = env.int("DJANGO_BROKER_VISIBILITY_TIMEOUT", default=86400)

celery_app = Celery("tasks")

celery_app.config_from_object("django.conf:settings", namespace="CELERY")
celery_app.conf.update(result_extended=True, result_expires=None)

celery_app.conf.broker_transport_options = {
    "visibility_timeout": BROKER_VISIBILITY_TIMEOUT
}
celery_app.conf.result_backend_transport_options = {
    "visibility_timeout": BROKER_VISIBILITY_TIMEOUT
}
celery_app.conf.visibility_timeout = BROKER_VISIBILITY_TIMEOUT

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
            APITask.objects.create(
                id=task_result_instance.task_id,
                tenant_id=tenant_id,
                task_runner_task=task_result_instance,
            )
        return result
