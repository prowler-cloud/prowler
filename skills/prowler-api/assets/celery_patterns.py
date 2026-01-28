# Prowler API - Celery Patterns Reference
# Reference for prowler-api skill

from datetime import datetime, timedelta, timezone
import json

from celery import chain, group, shared_task
from celery.exceptions import SoftTimeLimitExceeded
from celery.utils.log import get_task_logger
from django.db import OperationalError, transaction
from django_celery_beat.models import IntervalSchedule, PeriodicTask

from api.db_utils import rls_transaction
from api.decorators import handle_provider_deletion, set_tenant
from api.models import Provider, Scan
from config.celery import RLSTask

logger = get_task_logger(__name__)


# =============================================================================
# DECORATOR ORDER - CRITICAL
# =============================================================================
# @shared_task() must be first
# @set_tenant must be second (sets RLS context)
# @handle_provider_deletion must be third (handles deleted providers)


# =============================================================================
# @set_tenant BEHAVIOR
# =============================================================================


# Example: @set_tenant (default) - tenant_id NOT in function signature
# The decorator pops tenant_id from kwargs after setting RLS context
@shared_task(base=RLSTask, name="provider-connection-check")
@set_tenant
def check_provider_connection_task(provider_id: str):
    """Task receives NO tenant_id param - decorator pops it from kwargs."""
    # RLS context already set by decorator
    with rls_transaction():  # Context already established
        provider = Provider.objects.get(pk=provider_id)
        return {"connected": provider.connected}


# Example: @set_tenant(keep_tenant=True) - tenant_id IN function signature
@shared_task(base=RLSTask, name="scan-report", queue="scan-reports")
@set_tenant(keep_tenant=True)
def generate_outputs_task(scan_id: str, provider_id: str, tenant_id: str):
    """Task receives tenant_id param - use when function needs it."""
    # Can use tenant_id in function body
    with rls_transaction(tenant_id):
        scan = Scan.objects.get(pk=scan_id)
        # ... generate outputs
        return {"scan_id": scan_id, "tenant_id": tenant_id}


# =============================================================================
# TASK COMPOSITION (CANVAS)
# =============================================================================


# Chain: Sequential execution - A → B → C
def example_chain(tenant_id: str):
    """Tasks run one after another."""
    chain(
        task_a.si(tenant_id=tenant_id),
        task_b.si(tenant_id=tenant_id),
        task_c.si(tenant_id=tenant_id),
    ).apply_async()


# Group: Parallel execution - A, B, C simultaneously
def example_group(tenant_id: str):
    """Tasks run at the same time."""
    group(
        task_a.si(tenant_id=tenant_id),
        task_b.si(tenant_id=tenant_id),
        task_c.si(tenant_id=tenant_id),
    ).apply_async()


# Combined: Real pattern from Prowler (post-scan workflow)
def post_scan_workflow(tenant_id: str, scan_id: str, provider_id: str):
    """Chain with nested groups for complex workflows."""
    chain(
        # First: Summary
        perform_scan_summary_task.si(tenant_id=tenant_id, scan_id=scan_id),
        # Then: Parallel aggregation + outputs
        group(
            aggregate_daily_severity_task.si(tenant_id=tenant_id, scan_id=scan_id),
            generate_outputs_task.si(
                scan_id=scan_id, provider_id=provider_id, tenant_id=tenant_id
            ),
        ),
        # Finally: Parallel compliance + integrations
        group(
            generate_compliance_reports_task.si(
                tenant_id=tenant_id, scan_id=scan_id, provider_id=provider_id
            ),
            check_integrations_task.si(
                tenant_id=tenant_id, provider_id=provider_id, scan_id=scan_id
            ),
        ),
    ).apply_async()


# Note: Use .si() (signature immutable) to prevent result passing.
# Use .s() if you need to pass results between tasks.


# =============================================================================
# BEAT SCHEDULING (PERIODIC TASKS)
# =============================================================================


def schedule_provider_scan(provider_id: str, tenant_id: str):
    """Create a periodic task that runs every 24 hours."""
    # 1. Create or get the schedule
    schedule, _ = IntervalSchedule.objects.get_or_create(
        every=24,
        period=IntervalSchedule.HOURS,
    )

    # 2. Create the periodic task
    PeriodicTask.objects.create(
        interval=schedule,
        name=f"scan-perform-scheduled-{provider_id}",  # Unique name
        task="scan-perform-scheduled",  # Task name (not function name)
        kwargs=json.dumps(
            {
                "tenant_id": str(tenant_id),
                "provider_id": str(provider_id),
            }
        ),
        one_off=False,
        start_time=datetime.now(timezone.utc) + timedelta(hours=24),
    )


def delete_scheduled_scan(provider_id: str):
    """Remove a periodic task."""
    PeriodicTask.objects.filter(name=f"scan-perform-scheduled-{provider_id}").delete()


# Avoiding race conditions with countdown
def schedule_with_countdown(provider_id: str, tenant_id: str):
    """Use countdown to ensure DB transaction commits before task runs."""
    perform_scheduled_scan_task.apply_async(
        kwargs={"tenant_id": tenant_id, "provider_id": provider_id},
        countdown=5,  # Wait 5 seconds
    )


# =============================================================================
# ADVANCED TASK PATTERNS
# =============================================================================


# bind=True - Access task metadata
@shared_task(base=RLSTask, bind=True, name="scan-perform-scheduled", queue="scans")
@set_tenant(keep_tenant=True)
def perform_scheduled_scan_task(self, tenant_id: str, provider_id: str):
    """bind=True provides access to self.request for task metadata."""
    task_id = self.request.id  # Current task ID
    retries = self.request.retries  # Number of retries so far

    with rls_transaction(tenant_id):
        scan = Scan.objects.create(
            provider_id=provider_id,
            task_id=task_id,  # Track which task started this scan
        )
        return {"scan_id": str(scan.id), "task_id": task_id}


# get_task_logger - Proper logging in Celery tasks
@shared_task(base=RLSTask, name="my-task")
@set_tenant
def my_task_with_logging(provider_id: str):
    """Always use get_task_logger for Celery task logging."""
    logger.info(f"Processing provider {provider_id}")
    logger.warning("Potential issue detected")
    logger.error("Failed to process")

    # Called with tenant_id in kwargs (decorator handles it)
    # my_task_with_logging.delay(provider_id="...", tenant_id="...")


# SoftTimeLimitExceeded - Graceful timeout handling
@shared_task(
    base=RLSTask,
    soft_time_limit=300,  # 5 minutes - raises SoftTimeLimitExceeded
    time_limit=360,  # 6 minutes - hard kill (SIGKILL)
)
@set_tenant(keep_tenant=True)
def long_running_task(tenant_id: str, scan_id: str):
    """Handle soft time limits gracefully to save progress."""
    try:
        with rls_transaction(tenant_id):
            for batch in get_large_dataset():
                process_batch(batch)
    except SoftTimeLimitExceeded:
        logger.warning(f"Task soft limit exceeded for scan {scan_id}, saving progress...")
        save_partial_progress(scan_id)
        raise  # Re-raise to mark task as failed


# Deferred execution - countdown and eta
def deferred_examples():
    """Execute tasks at specific times."""
    # Execute after 30 seconds
    my_task.apply_async(kwargs={"provider_id": "..."}, countdown=30)

    # Execute at specific time
    my_task.apply_async(
        kwargs={"provider_id": "..."},
        eta=datetime(2024, 1, 15, 10, 0, tzinfo=timezone.utc),
    )


# =============================================================================
# CELERY CONFIGURATION (config/celery.py)
# =============================================================================

# Example configuration - see actual file for full config
"""
from celery import Celery

celery_app = Celery("tasks")
celery_app.config_from_object("django.conf:settings", namespace="CELERY")

# Visibility timeout - CRITICAL for long-running tasks
# If task takes longer than this, broker assumes worker died and re-queues
BROKER_VISIBILITY_TIMEOUT = 86400  # 24 hours for scan tasks

celery_app.conf.broker_transport_options = {
    "visibility_timeout": BROKER_VISIBILITY_TIMEOUT
}
celery_app.conf.result_backend_transport_options = {
    "visibility_timeout": BROKER_VISIBILITY_TIMEOUT
}

# Result settings
celery_app.conf.update(
    result_extended=True,   # Store additional task metadata
    result_expires=None,    # Never expire results (we manage cleanup)
)
"""

# Django settings (config/settings/celery.py)
"""
CELERY_BROKER_URL = f"redis://{VALKEY_HOST}:{VALKEY_PORT}/{VALKEY_DB}"
CELERY_RESULT_BACKEND = "django-db"  # Store results in PostgreSQL
CELERY_TASK_TRACK_STARTED = True     # Track when tasks start
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True

# Global time limits (optional)
CELERY_TASK_SOFT_TIME_LIMIT = 3600   # 1 hour soft limit
CELERY_TASK_TIME_LIMIT = 3660        # 1 hour + 1 minute hard limit
"""


# =============================================================================
# ASYNC TASK RESPONSE PATTERN (202 Accepted)
# =============================================================================


class ProviderViewSetExample:
    """Example: Return 202 for long-running operations."""

    def connection(self, request, pk=None):
        """Trigger async connection check, return 202 with task location."""
        from django.urls import reverse
        from rest_framework import status
        from rest_framework.response import Response

        from api.models import Task
        from api.v1.serializers import TaskSerializer

        with transaction.atomic():
            task = check_provider_connection_task.delay(
                provider_id=pk, tenant_id=self.request.tenant_id
            )
        prowler_task = Task.objects.get(id=task.id)
        serializer = TaskSerializer(prowler_task)
        return Response(
            data=serializer.data,
            status=status.HTTP_202_ACCEPTED,
            headers={
                "Content-Location": reverse("task-detail", kwargs={"pk": prowler_task.id})
            },
        )


# =============================================================================
# PLACEHOLDERS (would exist in real codebase)
# =============================================================================

task_a = None
task_b = None
task_c = None
perform_scan_summary_task = None
aggregate_daily_severity_task = None
generate_compliance_reports_task = None
check_integrations_task = None
perform_scheduled_scan_task = None
my_task = None


def get_large_dataset():
    return []


def process_batch(batch):
    pass


def save_partial_progress(scan_id):
    pass
