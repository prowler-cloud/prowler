from django.apps import AppConfig


class ApiConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "api"

    def ready(self):
        from api import signals  # noqa: F401
        from api.compliance import load_prowler_compliance

        load_prowler_compliance()
