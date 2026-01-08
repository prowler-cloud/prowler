# Example: Celery Tasks with RLS
# Source: api/src/backend/tasks/tasks.py

from celery import shared_task
from config.celery import RLSTask

from api.db_utils import rls_transaction
from api.decorators import handle_provider_deletion, set_tenant


@shared_task(base=RLSTask, name="provider-connection-check")
@set_tenant
def check_provider_connection_task(provider_id: str):
    """
    Task with @set_tenant decorator - pops tenant_id from kwargs.

    Key patterns:
    1. base=RLSTask for automatic task tracking in DB
    2. @set_tenant decorator handles RLS context setup
    3. tenant_id is passed via kwargs but popped by decorator
    """
    return check_provider_connection(provider_id=provider_id)


@shared_task(base=RLSTask, name="scan-perform", queue="scans")
@handle_provider_deletion
def perform_scan_task(
    tenant_id: str,
    scan_id: str,
    provider_id: str,
    checks_to_execute: list[str] = None,
):
    """
    Task with custom queue and error handling decorator.

    Key patterns:
    1. queue="scans" for dedicated worker queue
    2. @handle_provider_deletion handles cleanup on provider deletion
    3. Orchestrates follow-up tasks after completion
    """
    result = perform_prowler_scan(
        tenant_id=tenant_id,
        scan_id=scan_id,
        provider_id=provider_id,
        checks_to_execute=checks_to_execute,
    )
    _perform_scan_complete_tasks(tenant_id, scan_id, provider_id)
    return result


@shared_task(name="findings-mute-historical")
def mute_historical_findings_task(tenant_id: str, mute_rule_id: str):
    """
    Task without RLSTask base - uses rls_transaction manually.

    Key pattern: When not using RLSTask base, wrap DB operations in rls_transaction.
    """
    with rls_transaction(tenant_id):
        return mute_historical_findings(tenant_id, mute_rule_id)


# RLSTask base class (from config/celery.py)
class RLSTask(Task):
    """
    Celery Task base that tracks tasks in DB with tenant isolation.

    Key pattern: Override apply_async to create Task record in tenant context.
    """

    def apply_async(self, args=None, kwargs=None, task_id=None, **options):
        result = super().apply_async(
            args=args, kwargs=kwargs, task_id=task_id, **options
        )
        task_result_instance = TaskResult.objects.get(task_id=result.task_id)

        tenant_id = kwargs.get("tenant_id")
        with rls_transaction(tenant_id):
            APITask.objects.update_or_create(
                id=task_result_instance.task_id,
                tenant_id=tenant_id,
                defaults={"task_runner_task": task_result_instance},
            )
        return result
