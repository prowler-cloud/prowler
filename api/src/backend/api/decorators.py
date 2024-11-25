from functools import wraps

from django.db import connection, transaction


def set_tenant(func):
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
        some_task.delay(arg1, tenant_id="1234-abcd-5678")

        # The tenant context will be set before the task logic executes.
    """

    @wraps(func)
    @transaction.atomic
    def wrapper(*args, **kwargs):
        try:
            tenant_id = kwargs.pop("tenant_id")
        except KeyError:
            raise KeyError("This task requires the tenant_id")

        with connection.cursor() as cursor:
            cursor.execute(f"SELECT set_config('api.tenant_id', '{tenant_id}', TRUE);")

        return func(*args, **kwargs)

    return wrapper
