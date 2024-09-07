import time

from celery import Celery, Task
from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.exceptions import APIException

celery_app = Celery("tasks")

celery_app.config_from_object("django.conf:settings", namespace="CELERY")
celery_app.conf.update(result_extended=True)

celery_app.autodiscover_tasks(["api"])


class TaskTimeoutError(APIException):
    status_code = status.HTTP_504_GATEWAY_TIMEOUT
    default_detail = _("The request timed out")
    default_code = "service_unavailable_timeout"


class RLSTask(Task):
    def wait_for_task_result(self, result, timeout=10, poll_interval=0.1):
        """
        Wait for the Task runner task to be created, with a timeout.

        Args:
            result: The result object that contains the task_id.
            timeout: Maximum time to wait for the TaskResult to be created (in seconds).
            poll_interval: Time between each check (in seconds).

        Raises:
            TimeoutError: If the TaskResult is not created within the specified timeout.
        """
        from django_celery_results.models import TaskResult

        start_time = time.time()

        while not TaskResult.objects.filter(task_id=result.task_id).exists():
            if time.time() - start_time > timeout:
                raise TaskTimeoutError(
                    f"Task runner task was not created within {timeout} seconds"
                )
            time.sleep(poll_interval)

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
        # The TaskResult row is delayed a bit, so we need to wait for it to be created
        self.wait_for_task_result(result, timeout=10, poll_interval=0.05)
        task_result_instance = TaskResult.objects.get(task_id=result.task_id)
        APITask.objects.create(
            id=task_result_instance.task_id,
            tenant_id=kwargs.get("tenant_id"),
            task_runner_task=task_result_instance,
        )
        return result
