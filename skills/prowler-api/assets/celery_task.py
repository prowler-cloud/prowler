# Example: Celery Task Patterns
# Source: api/src/backend/tasks/tasks.py

import json
from datetime import datetime, timedelta

from celery import chain, group, shared_task
from config.celery import RLSTask
from django.utils import timezone
from django_celery_beat.models import IntervalSchedule, PeriodicTask

from api.db_utils import rls_transaction
from api.decorators import handle_provider_deletion, set_tenant
from api.models import Provider

# =============================================================================
# 1. Basic Task with RLS - Standard pattern for new tasks
# =============================================================================


@shared_task(base=RLSTask, name="my-task-name", queue="scans")
@set_tenant
@handle_provider_deletion
def my_task(tenant_id: str, provider_id: str):
    """
    Standard task pattern with both decorators.

    Decorators (order matters - outer to inner):
    - @set_tenant: Pops tenant_id from kwargs, sets PostgreSQL RLS context
    - @handle_provider_deletion: Catches ObjectDoesNotExist if provider deleted

    Note: Many tasks use only one decorator. Check existing tasks for patterns.

    Args:
        tenant_id: Extracted by @set_tenant, sets RLS context
        provider_id: Your task parameters
    """
    provider = Provider.objects.get(id=provider_id)
    # Your task logic here
    return {"status": "completed"}


# =============================================================================
# 2. Task without RLSTask base - Not tracked in APITask table
# =============================================================================


@shared_task(name="simple-task", queue="overview")
def simple_task(tenant_id: str, data: dict):
    """
    Task without RLSTask base.

    When NOT using RLSTask:
    - Task is NOT tracked in APITask table
    - Must manually use rls_transaction
    """
    with rls_transaction(tenant_id):
        # Your logic here
        pass


# =============================================================================
# 3. Task with Auto-Retry
# =============================================================================


@shared_task(
    base=RLSTask,
    name="retryable-task",
    queue="integrations",
    autoretry_for=(Exception,),
    retry_kwargs={"max_retries": 3, "countdown": 60},
)
@set_tenant
def retryable_task(tenant_id: str, integration_id: str):
    """
    Task with auto-retry on failure.

    autoretry_for: Exception types that trigger retry
    retry_kwargs: max_retries and countdown (seconds between retries)
    """
    # External API call that might fail


# =============================================================================
# 4. Task Orchestration - Sequential and Parallel execution
# =============================================================================


def orchestrate_tasks(tenant_id: str, scan_id: str):
    """
    Example of task orchestration.

    - chain(): Sequential execution (step1 -> step2 -> step3)
    - group(): Parallel execution (all at once)
    - .si(): "Signature immutable" - doesn't pass result to next task
    """
    # Independent tasks - fire immediately
    independent_task.apply_async(kwargs={"tenant_id": tenant_id})

    # Sequential with parallel groups
    workflow = chain(
        # Step 1: Must complete first
        step_one_task.si(tenant_id=tenant_id, scan_id=scan_id),
        # Step 2: After step 1, these run in parallel
        group(
            parallel_task_a.si(tenant_id=tenant_id, scan_id=scan_id),
            parallel_task_b.si(tenant_id=tenant_id, scan_id=scan_id),
        ),
    )

    workflow.apply_async()


# =============================================================================
# 5. Scheduled Task (Celery Beat)
# =============================================================================


def schedule_recurring_task(provider: Provider):
    """
    Schedule recurring task using Celery Beat.

    Uses django_celery_beat models:
    - IntervalSchedule: How often (24 hours, 1 hour, etc.)
    - PeriodicTask: The scheduled task
    """
    schedule, _ = IntervalSchedule.objects.get_or_create(
        every=24,
        period=IntervalSchedule.HOURS,
    )

    task_name = f"my-task-{provider.id}"
    PeriodicTask.objects.create(
        interval=schedule,
        name=task_name,
        task="my-task-name",  # Must match @shared_task name
        kwargs=json.dumps(
            {
                "tenant_id": str(provider.tenant_id),
                "provider_id": str(provider.id),
            }
        ),
        start_time=timezone.now() + timedelta(hours=24),
    )


def unschedule_task(provider_id: str):
    """Remove scheduled task."""
    task_name = f"my-task-{provider_id}"
    PeriodicTask.objects.filter(name=task_name).delete()


# =============================================================================
# 6. Calling Tasks
# =============================================================================


def trigger_task_examples():
    """Different ways to trigger tasks."""

    # Immediate execution
    my_task.apply_async(kwargs={"tenant_id": "uuid", "provider_id": "uuid"})

    # Delayed execution (5 seconds)
    my_task.apply_async(
        kwargs={"tenant_id": "uuid", "provider_id": "uuid"},
        countdown=5,
    )

    # Scheduled for specific time
    my_task.apply_async(
        kwargs={"tenant_id": "uuid", "provider_id": "uuid"},
        eta=datetime.now() + timedelta(hours=1),
    )
