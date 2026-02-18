import uuid
from functools import wraps

from django.core.exceptions import ObjectDoesNotExist
from django.db import DatabaseError, connection, transaction
from rest_framework_json_api.serializers import ValidationError

from api.db_router import READ_REPLICA_ALIAS
from api.db_utils import POSTGRES_TENANT_VAR, SET_CONFIG_QUERY, rls_transaction
from api.exceptions import ProviderDeletedException
from api.models import Provider, Scan


def set_tenant(func=None, *, keep_tenant=False):
    """
    Decorator to set the tenant context for a Celery task based on the provided tenant_id.

    This decorator extracts the `tenant_id` from the task's keyword arguments,
    and uses it to set the tenant context for the current database session.
    The `tenant_id` is then removed from the kwargs before the task function
    is executed. If `tenant_id` is not provided, a KeyError is raised.

    Args:
        func (function): The Celery task function to be decorated.

    Raises:
        KeyError: If `tenant_id` is not found in the task's keyword arguments.

    Returns:
        function: The wrapped function with tenant context set.

    Example:
        # This decorator MUST be defined the last in the decorator chain

        @shared_task
        @set_tenant
        def some_task(arg1, **kwargs):
            # Task logic here
            pass

        # When calling the task
        some_task.delay(arg1, tenant_id="8db7ca86-03cc-4d42-99f6-5e480baf6ab5")

        # The tenant context will be set before the task logic executes.
    """

    def decorator(func):
        @wraps(func)
        @transaction.atomic
        def wrapper(*args, **kwargs):
            try:
                if not keep_tenant:
                    tenant_id = kwargs.pop("tenant_id")
                else:
                    tenant_id = kwargs["tenant_id"]
            except KeyError:
                raise KeyError("This task requires the tenant_id")
            try:
                uuid.UUID(tenant_id)
            except ValueError:
                raise ValidationError("Tenant ID must be a valid UUID")
            with connection.cursor() as cursor:
                cursor.execute(SET_CONFIG_QUERY, [POSTGRES_TENANT_VAR, tenant_id])

            return func(*args, **kwargs)

        return wrapper

    if func is None:
        return decorator
    else:
        return decorator(func)


def handle_provider_deletion(func):
    """
    Decorator that raises `ProviderDeletedException` if provider was deleted during execution.

    Catches `ObjectDoesNotExist` and `DatabaseError` (including `IntegrityError`), checks if
    provider still exists, and raises `ProviderDeletedException` if not. Otherwise,
    re-raises original exception.

    Requires `tenant_id` and `provider_id` in kwargs.

    Example:
        @shared_task
        @handle_provider_deletion
        def scan_task(scan_id, tenant_id, provider_id):
            ...
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (ObjectDoesNotExist, DatabaseError):
            tenant_id = kwargs.get("tenant_id")
            provider_id = kwargs.get("provider_id")

            with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
                if provider_id is None:
                    scan_id = kwargs.get("scan_id")
                    if scan_id is None:
                        raise AssertionError(
                            "This task does not have provider or scan in the kwargs"
                        )
                    scan = Scan.objects.filter(pk=scan_id).first()
                    if scan is None:
                        raise ProviderDeletedException(
                            f"Provider for scan '{scan_id}' was deleted during the scan"
                        ) from None
                    provider_id = str(scan.provider_id)
                if not Provider.objects.filter(pk=provider_id).exists():
                    raise ProviderDeletedException(
                        f"Provider '{provider_id}' was deleted during the scan"
                    ) from None
            raise

    return wrapper
