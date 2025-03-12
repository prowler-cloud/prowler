from celery import states
from celery.signals import before_task_publish
from django.db.models.signals import post_delete
from django.dispatch import receiver
from django_celery_beat.models import PeriodicTask
from django_celery_results.backends.database import DatabaseBackend

from api.models import Provider
from config.celery import celery_app


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
    task_name = f"scan-perform-scheduled-{instance.id}"
    PeriodicTask.objects.filter(name=task_name).delete()
