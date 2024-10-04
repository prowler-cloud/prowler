from celery import Celery, Task

celery_app = Celery("tasks")

celery_app.config_from_object("django.conf:settings", namespace="CELERY")
celery_app.conf.update(result_extended=True)

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
        from api.models import Task as APITask
        from django_celery_results.models import TaskResult

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
        APITask.objects.create(
            id=task_result_instance.task_id,
            tenant_id=kwargs.get("tenant_id"),
            task_runner_task=task_result_instance,
        )
        return result
