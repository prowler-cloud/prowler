from celery import states
from celery.signals import before_task_publish
from config.celery import celery_app
from django.db.models.signals import post_delete, pre_delete
from django.dispatch import receiver
from django_celery_results.backends.database import DatabaseBackend

from api.db_utils import delete_related_daily_task
from api.models import (
    LighthouseProviderConfiguration,
    LighthouseTenantConfiguration,
    Membership,
    Provider,
    TenantAPIKey,
    User,
)


def create_task_result_on_publish(sender=None, headers=None, **kwargs):  # noqa: F841
    """Celery signal to store TaskResult entries when tasks reach the broker."""
    db_result_backend = DatabaseBackend(celery_app)
    request = type("request", (object,), headers)

    db_result_backend.store_result(
        headers["id"],
        None,
        states.PENDING,
        traceback=None,
        request=request,
    )


before_task_publish.connect(
    create_task_result_on_publish, dispatch_uid="create_task_result_on_publish"
)


@receiver(post_delete, sender=Provider)
def delete_provider_scan_task(sender, instance, **kwargs):  # noqa: F841
    # Delete the associated periodic task when the provider is deleted
    delete_related_daily_task(instance.id)


@receiver(pre_delete, sender=User)
def revoke_user_api_keys(sender, instance, **kwargs):  # noqa: F841
    """
    Revoke all API keys associated with a user before deletion.

    The entity field will be set to NULL by on_delete=SET_NULL,
    but we explicitly revoke the keys to prevent further use.
    """
    TenantAPIKey.objects.filter(entity=instance).update(revoked=True)


@receiver(post_delete, sender=Membership)
def revoke_membership_api_keys(sender, instance, **kwargs):  # noqa: F841
    """
    Revoke all API keys when a user is removed from a tenant.

    When a membership is deleted, all API keys created by that user
    in that tenant should be revoked to prevent further access.
    """
    TenantAPIKey.objects.filter(
        entity=instance.user, tenant_id=instance.tenant.id
    ).update(revoked=True)


@receiver(pre_delete, sender=LighthouseProviderConfiguration)
def cleanup_lighthouse_defaults_before_delete(sender, instance, **kwargs):  # noqa: F841
    """
    Ensure tenant Lighthouse defaults do not reference a soon-to-be-deleted provider.

    This runs for both per-instance deletes and queryset (bulk) deletes.
    """
    try:
        tenant_cfg = LighthouseTenantConfiguration.objects.get(
            tenant_id=instance.tenant_id
        )
    except LighthouseTenantConfiguration.DoesNotExist:
        return

    updated = False
    defaults = tenant_cfg.default_models or {}

    if instance.provider_type in defaults:
        defaults.pop(instance.provider_type, None)
        tenant_cfg.default_models = defaults
        updated = True

    if tenant_cfg.default_provider == instance.provider_type:
        tenant_cfg.default_provider = ""
        updated = True

    if updated:
        tenant_cfg.save()
