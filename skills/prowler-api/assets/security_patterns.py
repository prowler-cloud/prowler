# Example: Prowler API Security Patterns
# Reference for prowler-api skill

import uuid

from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.db import OperationalError, transaction
from rest_framework.exceptions import PermissionDenied

from api.db_utils import rls_transaction
from api.decorators import handle_provider_deletion, set_tenant
from api.models import Finding, Provider
from api.rls import Tenant
from tasks.base import RLSTask

# =============================================================================
# TENANT ISOLATION (RLS)
# =============================================================================


class ProviderViewSet:
    """Example: RLS context set automatically by BaseRLSViewSet."""

    def get_queryset(self):
        # RLS already filters by tenant_id from JWT
        # All queries are automatically tenant-scoped
        return Provider.objects.all()


@shared_task(base=RLSTask)
@set_tenant
def process_scan_good(tenant_id, scan_id):
    """GOOD: Explicit RLS context in Celery tasks."""
    with rls_transaction(tenant_id):
        # RLS enforced - only sees tenant's data
        scan = Scan.objects.get(id=scan_id)
        return scan


def dangerous_function(provider_id):
    """BAD: Bypassing RLS with admin database - exposes ALL tenants' data!"""
    # NEVER do this unless absolutely necessary for cross-tenant admin ops
    provider = Provider.objects.using("admin").get(id=provider_id)
    return provider


# =============================================================================
# CROSS-TENANT DATA LEAKAGE PREVENTION
# =============================================================================


class SecureViewSet:
    """Example: Defense-in-depth tenant validation."""

    def get_object(self):
        obj = super().get_object()
        # Defense-in-depth: verify tenant even though RLS should filter
        if obj.tenant_id != self.request.tenant_id:
            raise PermissionDenied("Access denied")
        return obj

    def create_good(self, request):
        """GOOD: Use tenant from authenticated JWT."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(tenant_id=request.tenant_id)

    def create_bad(self, request):
        """BAD: Trust user input for tenant_id."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        # NEVER trust user-provided tenant_id!
        serializer.save(tenant_id=request.data.get("tenant_id"))


# =============================================================================
# CELERY TASK SECURITY
# =============================================================================


@shared_task(base=RLSTask)
@set_tenant
def process_provider(tenant_id, provider_id):
    """Example: Validate task arguments before processing."""
    # Validate UUID format before database query
    try:
        uuid.UUID(provider_id)
    except ValueError:
        # Log and return - don't expose error details
        return {"error": "Invalid provider_id format"}

    with rls_transaction(tenant_id):
        # Now safe to query
        provider = Provider.objects.get(id=provider_id)
        return {"provider": str(provider.id)}


def send_task_bad(user_provided_task_name, args):
    """BAD: Dynamic task names from user input = arbitrary code execution."""
    from celery import current_app

    # NEVER do this!
    current_app.send_task(user_provided_task_name, args=args)


# =============================================================================
# SAFE TASK QUEUING WITH TRANSACTIONS
# =============================================================================


def create_provider_good(request, data):
    """GOOD: Task only enqueued AFTER transaction commits."""
    with transaction.atomic():
        provider = Provider.objects.create(**data)
        # Task enqueued only if transaction succeeds
        transaction.on_commit(
            lambda: verify_provider_connection.delay(
                tenant_id=str(request.tenant_id), provider_id=str(provider.id)
            )
        )
    return provider


def create_provider_bad(request, data):
    """BAD: Task enqueued before transaction commits - race condition!"""
    with transaction.atomic():
        provider = Provider.objects.create(**data)
        # Task might run before transaction commits!
        # If transaction rolls back, task processes non-existent data
        verify_provider_connection.delay(provider_id=str(provider.id))
    return provider


# =============================================================================
# MODERN CELERY RETRY PATTERNS
# =============================================================================


@shared_task(
    base=RLSTask,
    bind=True,
    # Automatic retry for transient errors
    autoretry_for=(ConnectionError, TimeoutError, OperationalError),
    retry_backoff=True,  # Exponential: 1s, 2s, 4s, 8s...
    retry_backoff_max=600,  # Cap at 10 minutes
    retry_jitter=True,  # Randomize to prevent thundering herd
    max_retries=5,
    # Time limits prevent hung tasks
    soft_time_limit=300,  # 5 min: raises SoftTimeLimitExceeded
    time_limit=360,  # 6 min: hard kill
)
@set_tenant
def sync_provider_data(self, tenant_id, provider_id):
    """Example: Modern retry pattern with time limits."""
    try:
        with rls_transaction(tenant_id):
            provider = Provider.objects.get(id=provider_id)
            # ... sync logic
            return {"status": "synced", "provider": str(provider.id)}
    except SoftTimeLimitExceeded:
        # Cleanup and exit gracefully
        return {"status": "timeout", "provider": provider_id}


# =============================================================================
# IDEMPOTENT TASK DESIGN
# =============================================================================


@shared_task(base=RLSTask, acks_late=True)
@set_tenant
def process_finding_good(tenant_id, finding_uid, data):
    """GOOD: Idempotent - safe to retry, uses upsert pattern."""
    with rls_transaction(tenant_id):
        # update_or_create is idempotent - retry won't create duplicates
        Finding.objects.update_or_create(uid=finding_uid, defaults=data)


@shared_task(base=RLSTask)
@set_tenant
def create_notification_bad(tenant_id, message):
    """BAD: Non-idempotent - retry creates duplicates."""
    with rls_transaction(tenant_id):
        # No dedup key - every retry creates a new notification!
        Notification.objects.create(message=message)


@shared_task(base=RLSTask, acks_late=True)
@set_tenant
def send_notification_good(tenant_id, idempotency_key, message):
    """GOOD: Idempotency key for non-upsertable operations."""
    with rls_transaction(tenant_id):
        # Check if already processed
        if ProcessedTask.objects.filter(key=idempotency_key).exists():
            return {"status": "already_processed"}

        Notification.objects.create(message=message)
        ProcessedTask.objects.create(key=idempotency_key)
        return {"status": "sent"}


# Placeholder for imports that would exist in real codebase
verify_provider_connection = None
Scan = None
Notification = None
ProcessedTask = None
