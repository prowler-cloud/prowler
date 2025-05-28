from django.urls import reverse
from django_celery_results.models import TaskResult
from rest_framework import status
from rest_framework.response import Response

from api.exceptions import (
    TaskFailedException,
    TaskInProgressException,
    TaskNotFoundException,
)
from api.models import StateChoices, Task
from api.v1.serializers import TaskSerializer


class PaginateByPkMixin:
    """
    Mixin to paginate on a list of PKs (cheaper than heavy JOINs),
    re-fetch the full objects with the desired select/prefetch,
    re-sort them to preserve DB ordering, then serialize + return.
    """

    def paginate_by_pk(
        self,
        request,  # noqa: F841
        base_queryset,
        manager,
        select_related: list[str] | None = None,
        prefetch_related: list[str] | None = None,
    ) -> Response:
        pk_list = base_queryset.values_list("id", flat=True)
        page = self.paginate_queryset(pk_list)
        if page is None:
            return Response(self.get_serializer(base_queryset, many=True).data)

        queryset = manager.filter(id__in=page)
        if select_related:
            queryset = queryset.select_related(*select_related)
        if prefetch_related:
            queryset = queryset.prefetch_related(*prefetch_related)

        queryset = sorted(queryset, key=lambda obj: page.index(obj.id))

        serialized = self.get_serializer(queryset, many=True).data
        return self.get_paginated_response(serialized)


class TaskManagementMixin:
    """
    Mixin to manage task status checking.

    This mixin provides functionality to check if a task with specific parameters
    is running, completed, failed, or doesn't exist. It returns the task when running
    and raises specific exceptions for failed/not found scenarios that can be handled
    at the view level.
    """

    def check_task_status(
        self,
        task_name: str,
        task_kwargs: dict,
        raise_on_failed: bool = True,
        raise_on_not_found: bool = True,
    ) -> Task | None:
        """
        Check the status of a task with given name and kwargs.

        This method first checks for a related Task object, and if not found,
        checks TaskResult directly. If a TaskResult is found and running but
        there's no related Task, it raises TaskInProgressException.

        Args:
            task_name (str): The name of the task to check
            task_kwargs (dict): The kwargs to match against the task
            raise_on_failed (bool): Whether to raise exception if task failed
            raise_on_not_found (bool): Whether to raise exception if task not found

        Returns:
            Task | None: The task instance if found (regardless of state), None if not found and raise_on_not_found=False

        Raises:
            TaskFailedException: If task failed and raise_on_failed=True
            TaskNotFoundException: If task not found and raise_on_not_found=True
            TaskInProgressException: If task is running but no related Task object exists
        """
        # First, try to find a Task object with related TaskResult
        try:
            # Build the filter for task kwargs
            task_filter = {
                "task_runner_task__task_name": task_name,
            }

            # Add kwargs filters - we need to check if the task kwargs contain our parameters
            for key, value in task_kwargs.items():
                task_filter["task_runner_task__task_kwargs__contains"] = str(value)

            task = (
                Task.objects.filter(**task_filter)
                .select_related("task_runner_task")
                .order_by("-inserted_at")
                .first()
            )

            if task:
                # Get task state using the same logic as TaskSerializer
                task_state_mapping = {
                    "PENDING": StateChoices.AVAILABLE,
                    "STARTED": StateChoices.EXECUTING,
                    "PROGRESS": StateChoices.EXECUTING,
                    "SUCCESS": StateChoices.COMPLETED,
                    "FAILURE": StateChoices.FAILED,
                    "REVOKED": StateChoices.CANCELLED,
                }

                celery_status = (
                    task.task_runner_task.status if task.task_runner_task else None
                )
                task_state = task_state_mapping.get(
                    celery_status or "", StateChoices.AVAILABLE
                )

                # Check task state and raise exceptions accordingly
                if task_state in (StateChoices.FAILED, StateChoices.CANCELLED):
                    if raise_on_failed:
                        raise TaskFailedException(task=task)
                    return task
                elif task_state == StateChoices.COMPLETED:
                    return None

                return task

        except Task.DoesNotExist:
            pass

        # If no Task found, check TaskResult directly
        try:
            # Build the filter for TaskResult
            task_result_filter = {
                "task_name": task_name,
            }

            # Add kwargs filters - check if the task kwargs contain our parameters
            for key, value in task_kwargs.items():
                task_result_filter["task_kwargs__contains"] = str(value)

            task_result = (
                TaskResult.objects.filter(**task_result_filter)
                .order_by("-date_created")
                .first()
            )

            if task_result:
                # Check if the TaskResult indicates a running task
                if task_result.status in ["PENDING", "STARTED", "PROGRESS"]:
                    # Task is running but no related Task object exists
                    raise TaskInProgressException(task_result=task_result)
                elif task_result.status == "FAILURE":
                    if raise_on_failed:
                        raise TaskFailedException(task=None)
                # For other statuses (SUCCESS, REVOKED), we don't have a Task to return,
                # so we treat it as not found

        except TaskResult.DoesNotExist:
            pass

        # No task found at all
        if raise_on_not_found:
            raise TaskNotFoundException()
        return None

    def get_task_response_if_running(
        self,
        task_name: str,
        task_kwargs: dict,
        raise_on_failed: bool = True,
        raise_on_not_found: bool = True,
    ) -> Response | None:
        """
        Get a 202 response with task details if the task is currently running.

        This method is useful for endpoints that should return task status when
        a background task is in progress, similar to the compliance overview endpoints.

        Args:
            task_name (str): The name of the task to check
            task_kwargs (dict): The kwargs to match against the task

        Returns:
            Response | None: 202 response with task details if running, None otherwise
        """
        task = self.check_task_status(
            task_name=task_name,
            task_kwargs=task_kwargs,
            raise_on_failed=raise_on_failed,
            raise_on_not_found=raise_on_not_found,
        )

        if not task:
            return None

        # Get task state
        task_state_mapping = {
            "PENDING": StateChoices.AVAILABLE,
            "STARTED": StateChoices.EXECUTING,
            "PROGRESS": StateChoices.EXECUTING,
            "SUCCESS": StateChoices.COMPLETED,
            "FAILURE": StateChoices.FAILED,
            "REVOKED": StateChoices.CANCELLED,
        }

        celery_status = task.task_runner_task.status if task.task_runner_task else None
        task_state = task_state_mapping.get(celery_status or "", StateChoices.AVAILABLE)

        if task_state == StateChoices.EXECUTING:
            self.response_serializer_class = TaskSerializer
            serializer = TaskSerializer(task)
            return Response(
                data=serializer.data,
                status=status.HTTP_202_ACCEPTED,
                headers={
                    "Content-Location": reverse("task-detail", kwargs={"pk": task.id})
                },
            )
