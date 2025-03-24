ALLOWED_APPS = ("django", "socialaccount", "account", "authtoken", "silk")


class MainRouter:
    default_db = "default"
    admin_db = "admin"

    def db_for_read(self, model, **hints):  # noqa: F841
        model_table_name = model._meta.db_table
        if model_table_name.startswith("django_") or any(
            model_table_name.startswith(f"{app}_") for app in ALLOWED_APPS
        ):
            return self.admin_db
        return None

    def db_for_write(self, model, **hints):  # noqa: F841
        model_table_name = model._meta.db_table
        if any(model_table_name.startswith(f"{app}_") for app in ALLOWED_APPS):
            return self.admin_db
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):  # noqa: F841
        return db == self.admin_db

    def allow_relation(self, obj1, obj2, **hints):  # noqa: F841
        # Allow relations if both objects are in either "default" or "admin" db connectors
        if {obj1._state.db, obj2._state.db} <= {self.default_db, self.admin_db}:
            return True
        return None
