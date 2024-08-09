from celery import Celery


celery_app = Celery("tasks")

celery_app.config_from_object("django.conf:settings", namespace="CELERY")

celery_app.autodiscover_tasks(["tasks"])
