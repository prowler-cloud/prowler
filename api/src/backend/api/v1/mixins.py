import uuid

from api.exceptions import (
    TaskFailedException,
    TaskInProgressException,
    TaskNotFoundException,
)
from api.models import Provider, StateChoices, Task
from api.v1.serializers import TaskSerializer
from django.http import QueryDict
from django.urls import reverse
from django_celery_results.models import TaskResult
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response


class DisablePaginationMixin:
    disable_pagination_query_param = "page[disable]"
    disable_pagination_truthy_values = {"true"}

    def should_disable_pagination(self) -> bool:
        if not hasattr(self, "request"):
            return False
        value = self.request.query_params.get(self.disable_pagination_query_param)
        if value is None:
            return False
        return str(value).lower() in self.disable_pagination_truthy_values

    def paginate_queryset(self, queryset):
        if self.should_disable_pagination():
            return None
        return super().paginate_queryset(queryset)


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
        select_related: list | None = None,
        prefetch_related: list | None = None,
    ) -> Response:
        """
        Paginate a queryset by primary key.

        This method is useful when you want to paginate a queryset that has been
        filtered or annotated in a way that would be lost if you used the default
        pagination method.
        """
        pk_list = base_queryset.values_list("id", flat=True)
        page = self.paginate_queryset(pk_list)
        if page is None:
            return Response(self.get_serializer(base_queryset, many=True).data)

        queryset = manager.filter(id__in=page)

        if select_related:
            queryset = queryset.select_related(*select_related)
        if prefetch_related:
            queryset = queryset.prefetch_related(*prefetch_related)

        # Optimize tags loading, if applicable
        if hasattr(self, "_optimize_tags_loading"):
            queryset = self._optimize_tags_loading(queryset)

        queryset = sorted(queryset, key=lambda obj: page.index(obj.id))

        serialized = self.get_serializer(queryset, many=True).data
        return self.get_paginated_response(serialized)


class JsonApiFilterMixin:
    """Shared helpers for manually applying django-filter to JSON:API params."""

    jsonapi_filter_replace_dots = False

    def _normalize_jsonapi_params(
        self,
        query_params,
        exclude_keys=None,
        replace_dots=None,
    ):
        exclude_keys = exclude_keys or set()
        if replace_dots is None:
            replace_dots = self.jsonapi_filter_replace_dots

        normalized = QueryDict(mutable=True)
        for key, values in query_params.lists():
            normalized_key = (
                key[7:-1] if key.startswith("filter[") and key.endswith("]") else key
            )
            if replace_dots:
                normalized_key = normalized_key.replace(".", "__")
            if normalized_key not in exclude_keys:
                normalized.setlist(normalized_key, values)
        return normalized

    def _apply_filterset(
        self,
        queryset,
        filterset_class,
        exclude_keys=None,
        replace_dots=None,
    ):
        normalized_params = self._normalize_jsonapi_params(
            self.request.query_params,
            exclude_keys=set(exclude_keys or []),
            replace_dots=replace_dots,
        )
        filterset = filterset_class(normalized_params, queryset=queryset)
        if not filterset.is_valid():
            raise ValidationError(filterset.errors)
        return filterset.qs


class ProviderFilterParamsMixin(JsonApiFilterMixin):
    """Shared extraction of provider filters from JSON:API query params."""

    PROVIDER_FILTER_KEYS = frozenset(
        {
            "provider_id",
            "provider_id__in",
            "provider_type",
            "provider_type__in",
            "provider_groups",
            "provider_groups__in",
        }
    )
    PROVIDER_FILTER_DOT_ALIAS_KEYS = frozenset(
        {
            "provider_id.in",
            "provider_type.in",
            "provider_groups.in",
        }
    )
    PROVIDER_FILTER_QUERY_KEYS = PROVIDER_FILTER_KEYS | PROVIDER_FILTER_DOT_ALIAS_KEYS

    def _csv_filter_values(self, value):
        return [item.strip() for item in value.split(",") if item.strip()]

    def _validate_uuid_filter_values(self, field_name, values):
        try:
            for value in values:
                uuid.UUID(str(value))
        except (TypeError, ValueError, AttributeError):
            raise ValidationError({field_name: ["Enter a valid UUID."]})

    def _has_provider_filters(self, include_dot_aliases=False):
        provider_filter_keys = (
            self.PROVIDER_FILTER_QUERY_KEYS
            if include_dot_aliases
            else self.PROVIDER_FILTER_KEYS
        )
        return any(
            self.request.query_params.get(f"filter[{key}]")
            for key in provider_filter_keys
        )

    def _extract_provider_filters_from_params(
        self,
        *,
        validate_uuids=False,
        include_dot_aliases=False,
    ):
        params = self.request.query_params
        filters = {}
        valid_provider_types = {
            choice[0] for choice in Provider.ProviderChoices.choices
        }

        provider_id = params.get("filter[provider_id]")
        if provider_id:
            if validate_uuids:
                self._validate_uuid_filter_values("provider_id", [provider_id])
            filters["provider_id"] = provider_id

        provider_id_in = params.get("filter[provider_id__in]")
        if include_dot_aliases:
            provider_id_in = provider_id_in or params.get("filter[provider_id.in]")
        if provider_id_in:
            values = self._csv_filter_values(provider_id_in)
            if validate_uuids:
                self._validate_uuid_filter_values("provider_id__in", values)
            filters["provider_id__in"] = values

        provider_type = params.get("filter[provider_type]")
        if provider_type:
            if provider_type not in valid_provider_types:
                raise ValidationError(
                    {"provider_type": f"Invalid choice: {provider_type}"}
                )
            filters["provider__provider"] = provider_type

        provider_type_in = params.get("filter[provider_type__in]")
        if include_dot_aliases:
            provider_type_in = provider_type_in or params.get(
                "filter[provider_type.in]"
            )
        if provider_type_in:
            values = self._csv_filter_values(provider_type_in)
            invalid = [value for value in values if value not in valid_provider_types]
            if invalid:
                raise ValidationError(
                    {"provider_type__in": f"Invalid choices: {', '.join(invalid)}"}
                )
            filters["provider__provider__in"] = values

        provider_groups = params.get("filter[provider_groups]")
        if provider_groups:
            if validate_uuids:
                self._validate_uuid_filter_values("provider_groups", [provider_groups])
            filters["provider__provider_groups__id"] = provider_groups

        provider_groups_in = params.get("filter[provider_groups__in]")
        if include_dot_aliases:
            provider_groups_in = provider_groups_in or params.get(
                "filter[provider_groups.in]"
            )
        if provider_groups_in:
            values = self._csv_filter_values(provider_groups_in)
            if validate_uuids:
                self._validate_uuid_filter_values("provider_groups__in", values)
            filters["provider__provider_groups__id__in"] = values

        return filters


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
