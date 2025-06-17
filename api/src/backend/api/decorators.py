from functools import wraps

from api.db_utils import rls_transaction


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
        def wrapper(*args, **kwargs):
            try:
                if not keep_tenant:
                    tenant_id = kwargs.pop("tenant_id")
                else:
                    tenant_id = kwargs["tenant_id"]
            except KeyError:
                raise KeyError("This task requires the tenant_id")
            with rls_transaction(tenant_id):
                return func(*args, **kwargs)

        return wrapper

    if func is None:
        return decorator
    else:
        return decorator(func)
