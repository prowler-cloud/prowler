import json
from uuid import uuid4

import pytest
from django_celery_results.models import TaskResult
from rest_framework import status
from rest_framework.response import Response

from api.exceptions import (
    TaskFailedException,
    TaskInProgressException,
    TaskNotFoundException,
)
from api.models import Task, User
from api.rls import Tenant
from api.v1.mixins import PaginateByPkMixin, TaskManagementMixin


@pytest.mark.django_db
class TestPaginateByPkMixin:
    @pytest.fixture
    def tenant(self):
        return Tenant.objects.create(name="Test Tenant")

    @pytest.fixture
    def users(self, tenant):
        # Create 5 users with proper email field
        users = []
        for i in range(5):
            user = User.objects.create(email=f"user{i}@example.com", name=f"User {i}")
            users.append(user)
        return users

    class DummyView(PaginateByPkMixin):
        def __init__(self, page):
            self._page = page

        def paginate_queryset(self, qs):
            return self._page

        def get_serializer(self, queryset, many):
            class S:
                def __init__(self, data):
                    # serialize to list of ids
                    self.data = [obj.id for obj in data] if many else queryset.id

            return S(queryset)

        def get_paginated_response(self, data):
            return Response({"results": data}, status=status.HTTP_200_OK)

    def test_no_pagination(self, users):
        base_qs = User.objects.all().order_by("id")
        view = self.DummyView(page=None)
        resp = view.paginate_by_pk(
            request=None, base_queryset=base_qs, manager=User.objects
        )
        # since no pagination, should return all ids in order
        expected = [u.id for u in base_qs]
        assert isinstance(resp, Response)
        assert resp.data == expected

    def test_with_pagination(self, users):
        base_qs = User.objects.all().order_by("id")
        # simulate paging to first 2 ids
        page = [base_qs[1].id, base_qs[3].id]
        view = self.DummyView(page=page)
        resp = view.paginate_by_pk(
            request=None, base_queryset=base_qs, manager=User.objects
        )
        # should fetch only those two users, in the same order as page
        assert resp.status_code == status.HTTP_200_OK
        assert resp.data == {"results": page}


@pytest.mark.django_db
class TestTaskManagementMixin:
    class DummyView(TaskManagementMixin):
        pass

    @pytest.fixture
    def tenant(self):
        return Tenant.objects.create(name="Test Tenant")

    @pytest.fixture(autouse=True)
    def cleanup(self):
        Task.objects.all().delete()
        TaskResult.objects.all().delete()

    def test_no_task_and_no_taskresult_raises_not_found(self):
        view = self.DummyView()
        with pytest.raises(TaskNotFoundException):
            view.check_task_status("task_xyz", {"foo": "bar"})

    def test_no_task_and_no_taskresult_returns_none_when_not_raising(self):
        view = self.DummyView()
        result = view.check_task_status(
            "task_xyz", {"foo": "bar"}, raise_on_not_found=False
        )
        assert result is None

    def test_taskresult_pending_raises_in_progress(self):
        task_kwargs = {"foo": "bar"}
        tr = TaskResult.objects.create(
            task_id=str(uuid4()),
            task_name="task_xyz",
            task_kwargs=json.dumps(task_kwargs),
            status="PENDING",
        )
        view = self.DummyView()
        with pytest.raises(TaskInProgressException) as excinfo:
            view.check_task_status("task_xyz", task_kwargs, raise_on_not_found=False)
        assert hasattr(excinfo.value, "task_result")
        assert excinfo.value.task_result == tr

    def test_taskresult_started_raises_in_progress(self):
        task_kwargs = {"foo": "bar"}
        tr = TaskResult.objects.create(
            task_id=str(uuid4()),
            task_name="task_xyz",
            task_kwargs=json.dumps(task_kwargs),
            status="STARTED",
        )
        view = self.DummyView()
        with pytest.raises(TaskInProgressException) as excinfo:
            view.check_task_status("task_xyz", task_kwargs, raise_on_not_found=False)
        assert hasattr(excinfo.value, "task_result")
        assert excinfo.value.task_result == tr

    def test_taskresult_progress_raises_in_progress(self):
        task_kwargs = {"foo": "bar"}
        tr = TaskResult.objects.create(
            task_id=str(uuid4()),
            task_name="task_xyz",
            task_kwargs=json.dumps(task_kwargs),
            status="PROGRESS",
        )
        view = self.DummyView()
        with pytest.raises(TaskInProgressException) as excinfo:
            view.check_task_status("task_xyz", task_kwargs, raise_on_not_found=False)
        assert hasattr(excinfo.value, "task_result")
        assert excinfo.value.task_result == tr

    def test_taskresult_failure_raises_failed(self):
        task_kwargs = {"a": 1}
        TaskResult.objects.create(
            task_id=str(uuid4()),
            task_name="task_fail",
            task_kwargs=json.dumps(task_kwargs),
            status="FAILURE",
        )
        view = self.DummyView()
        with pytest.raises(TaskFailedException):
            view.check_task_status("task_fail", task_kwargs, raise_on_not_found=False)

    def test_taskresult_failure_returns_none_when_not_raising(self):
        task_kwargs = {"a": 1}
        TaskResult.objects.create(
            task_id=str(uuid4()),
            task_name="task_fail",
            task_kwargs=json.dumps(task_kwargs),
            status="FAILURE",
        )
        view = self.DummyView()
        result = view.check_task_status(
            "task_fail", task_kwargs, raise_on_failed=False, raise_on_not_found=False
        )
        assert result is None

    def test_taskresult_success_returns_none(self):
        task_kwargs = {"x": 2}
        TaskResult.objects.create(
            task_id=str(uuid4()),
            task_name="task_ok",
            task_kwargs=json.dumps(task_kwargs),
            status="SUCCESS",
        )
        view = self.DummyView()
        # should not raise, and returns None
        assert (
            view.check_task_status("task_ok", task_kwargs, raise_on_not_found=False)
            is None
        )

    def test_taskresult_revoked_returns_none(self):
        task_kwargs = {"x": 2}
        TaskResult.objects.create(
            task_id=str(uuid4()),
            task_name="task_revoked",
            task_kwargs=json.dumps(task_kwargs),
            status="REVOKED",
        )
        view = self.DummyView()
        # should not raise, and returns None
        assert (
            view.check_task_status(
                "task_revoked", task_kwargs, raise_on_not_found=False
            )
            is None
        )

    def test_task_with_failed_status_raises_failed(self, tenant):
        task_kwargs = {"provider_id": "test"}
        tr = TaskResult.objects.create(
            task_id=str(uuid4()),
            task_name="scan_task",
            task_kwargs=json.dumps(task_kwargs),
            status="FAILURE",
        )
        task = Task.objects.create(tenant=tenant, task_runner_task=tr)
        view = self.DummyView()
        with pytest.raises(TaskFailedException) as excinfo:
            view.check_task_status("scan_task", task_kwargs)
        # Check that the exception contains the expected task
        assert hasattr(excinfo.value, "task")
        assert excinfo.value.task == task

    def test_task_with_cancelled_status_raises_failed(self, tenant):
        task_kwargs = {"provider_id": "test"}
        tr = TaskResult.objects.create(
            task_id=str(uuid4()),
            task_name="scan_task",
            task_kwargs=json.dumps(task_kwargs),
            status="REVOKED",
        )
        task = Task.objects.create(tenant=tenant, task_runner_task=tr)
        view = self.DummyView()
        with pytest.raises(TaskFailedException) as excinfo:
            view.check_task_status("scan_task", task_kwargs)
        # Check that the exception contains the expected task
        assert hasattr(excinfo.value, "task")
        assert excinfo.value.task == task

    def test_task_with_failed_status_returns_task_when_not_raising(self, tenant):
        task_kwargs = {"provider_id": "test"}
        tr = TaskResult.objects.create(
            task_id=str(uuid4()),
            task_name="scan_task",
            task_kwargs=json.dumps(task_kwargs),
            status="FAILURE",
        )
        task = Task.objects.create(tenant=tenant, task_runner_task=tr)
        view = self.DummyView()
        result = view.check_task_status("scan_task", task_kwargs, raise_on_failed=False)
        assert result == task

    def test_task_with_completed_status_returns_none(self, tenant):
        task_kwargs = {"provider_id": "test"}
        tr = TaskResult.objects.create(
            task_id=str(uuid4()),
            task_name="scan_task",
            task_kwargs=json.dumps(task_kwargs),
            status="SUCCESS",
        )
        Task.objects.create(tenant=tenant, task_runner_task=tr)
        view = self.DummyView()
        result = view.check_task_status("scan_task", task_kwargs)
        assert result is None

    def test_task_with_executing_status_returns_task(self, tenant):
        task_kwargs = {"provider_id": "test"}
        tr = TaskResult.objects.create(
            task_id=str(uuid4()),
            task_name="scan_task",
            task_kwargs=json.dumps(task_kwargs),
            status="STARTED",
        )
        task = Task.objects.create(tenant=tenant, task_runner_task=tr)
        view = self.DummyView()
        result = view.check_task_status("scan_task", task_kwargs)
        assert result is not None
        assert result.pk == task.pk

    def test_task_with_pending_status_returns_task(self, tenant):
        task_kwargs = {"provider_id": "test"}
        tr = TaskResult.objects.create(
            task_id=str(uuid4()),
            task_name="scan_task",
            task_kwargs=json.dumps(task_kwargs),
            status="PENDING",
        )
        task = Task.objects.create(tenant=tenant, task_runner_task=tr)
        view = self.DummyView()
        result = view.check_task_status("scan_task", task_kwargs)
        assert result is not None
        assert result.pk == task.pk

    def test_get_task_response_if_running_returns_none_for_completed_task(self, tenant):
        task_kwargs = {"provider_id": "test"}
        tr = TaskResult.objects.create(
            task_id=str(uuid4()),
            task_name="scan_task",
            task_kwargs=json.dumps(task_kwargs),
            status="SUCCESS",
        )
        Task.objects.create(tenant=tenant, task_runner_task=tr)
        view = self.DummyView()
        result = view.get_task_response_if_running("scan_task", task_kwargs)
        assert result is None

    def test_get_task_response_if_running_returns_none_for_no_task(self):
        view = self.DummyView()
        result = view.get_task_response_if_running(
            "nonexistent", {"foo": "bar"}, raise_on_not_found=False
        )
        assert result is None

    def test_get_task_response_if_running_returns_202_for_executing_task(self, tenant):
        task_kwargs = {"provider_id": "test"}
        tr = TaskResult.objects.create(
            task_id=str(uuid4()),
            task_name="scan_task",
            task_kwargs=json.dumps(task_kwargs),
            status="STARTED",
        )
        task = Task.objects.create(tenant=tenant, task_runner_task=tr)
        view = self.DummyView()
        result = view.get_task_response_if_running("scan_task", task_kwargs)

        assert isinstance(result, Response)
        assert result.status_code == status.HTTP_202_ACCEPTED
        assert "Content-Location" in result.headers
        # The response should contain the serialized task data
        assert result.data is not None
        assert "id" in result.data
        assert str(result.data["id"]) == str(task.id)

    def test_get_task_response_if_running_returns_none_for_available_task(self, tenant):
        task_kwargs = {"provider_id": "test"}
        tr = TaskResult.objects.create(
            task_id=str(uuid4()),
            task_name="scan_task",
            task_kwargs=json.dumps(task_kwargs),
            status="PENDING",
        )
        Task.objects.create(tenant=tenant, task_runner_task=tr)
        view = self.DummyView()
        result = view.get_task_response_if_running("scan_task", task_kwargs)
        # PENDING maps to AVAILABLE, which is not EXECUTING, so should return None
        assert result is None

    def test_kwargs_filtering_works_correctly(self, tenant):
        # Create tasks with different kwargs
        task_kwargs_1 = {"provider_id": "test1", "scan_type": "full"}
        task_kwargs_2 = {"provider_id": "test2", "scan_type": "quick"}

        tr1 = TaskResult.objects.create(
            task_id=str(uuid4()),
            task_name="scan_task",
            task_kwargs=json.dumps(task_kwargs_1),
            status="STARTED",
        )
        tr2 = TaskResult.objects.create(
            task_id=str(uuid4()),
            task_name="scan_task",
            task_kwargs=json.dumps(task_kwargs_2),
            status="STARTED",
        )

        task1 = Task.objects.create(tenant=tenant, task_runner_task=tr1)
        task2 = Task.objects.create(tenant=tenant, task_runner_task=tr2)

        view = self.DummyView()

        # Should find task1 when searching for its kwargs
        result1 = view.check_task_status("scan_task", {"provider_id": "test1"})
        assert result1 is not None
        assert result1.pk == task1.pk

        # Should find task2 when searching for its kwargs
        result2 = view.check_task_status("scan_task", {"provider_id": "test2"})
        assert result2 is not None
        assert result2.pk == task2.pk

        # Should not find anything when searching for non-existent kwargs
        result3 = view.check_task_status(
            "scan_task", {"provider_id": "test3"}, raise_on_not_found=False
        )
        assert result3 is None
