class MainRouter:
    default_db = "default"
    admin_db = "admin"

    def db_for_read(self, model, **hints):  # noqa: F841
        model_table_name = model._meta.db_table
        if model_table_name.startswith("django_"):
            return self.admin_db
        return None

    def db_for_write(self, model, **hints):  # noqa: F841
        model_table_name = model._meta.db_table
        if model_table_name.startswith("django_"):
            return self.admin_db
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):  # noqa: F841
        return db == self.admin_db
