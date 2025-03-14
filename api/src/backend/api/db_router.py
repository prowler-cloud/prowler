ALLOWED_APPS = ("django", "socialaccount", "account", "authtoken", "silk")


class MainRouter:
    default_db = "default"
    default_read = "default_read"
    admin_db = "admin"
    admin_read = "admin_read"

    def db_for_read(self, model, **hints):  # noqa: F841
        model_table_name = model._meta.db_table
        if any(model_table_name.startswith(f"{app}_") for app in ALLOWED_APPS):
            return self.admin_read
        return self.default_read

    def db_for_write(self, model, **hints):  # noqa: F841
        model_table_name = model._meta.db_table
        if any(model_table_name.startswith(f"{app}_") for app in ALLOWED_APPS):
            return self.admin_db
        return self.default_db

    def allow_migrate(self, db, app_label, model_name=None, **hints):  # noqa: F841
        return db == self.admin_db

    def allow_relation(self, obj1, obj2, **hints):  # noqa: F841
        # Allow relations if both objects are using one of our defined connectors
        allowed = {self.default_db, self.default_read, self.admin_db, self.admin_read}
        if {obj1._state.db, obj2._state.db} <= allowed:
            return True
        return None
