from contextlib import contextmanager
from contextvars import ContextVar

from django.conf import settings

ALLOWED_APPS = ("django", "socialaccount", "account", "authtoken", "silk")

_read_db_alias = ContextVar("read_db_alias", default=None)
_write_db_alias = ContextVar("write_db_alias", default=None)


def set_read_db_alias(alias: str | None):
    if not alias:
        return None
    return _read_db_alias.set(alias)


def get_read_db_alias() -> str | None:
    return _read_db_alias.get()


def reset_read_db_alias(token) -> None:
    if token is not None:
        _read_db_alias.reset(token)


def set_write_db_alias(alias: str | None):
    if not alias:
        return None
    return _write_db_alias.set(alias)


def get_write_db_alias() -> str | None:
    return _write_db_alias.get()


def reset_write_db_alias(token) -> None:
    if token is not None:
        _write_db_alias.reset(token)


@contextmanager
def write_db_alias(alias: str | None):
    token = set_write_db_alias(alias)
    try:
        yield
    finally:
        reset_write_db_alias(token)


class MainRouter:
    default_db = "default"
    admin_db = "admin"
    replica_db = "replica"
    admin_replica_db = "admin_replica"

    def db_for_read(self, model, **hints):  # noqa: F841
        model_table_name = model._meta.db_table
        if model_table_name.startswith("django_") or any(
            model_table_name.startswith(f"{app}_") for app in ALLOWED_APPS
        ):
            return self.admin_db
        read_alias = get_read_db_alias()
        if read_alias:
            return read_alias
        return None

    def db_for_write(self, model, **hints):  # noqa: F841
        model_table_name = model._meta.db_table
        if any(model_table_name.startswith(f"{app}_") for app in ALLOWED_APPS):
            return self.admin_db
        write_alias = get_write_db_alias()
        if write_alias:
            return write_alias
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):  # noqa: F841
        return db == self.admin_db

    def allow_relation(self, obj1, obj2, **hints):  # noqa: F841
        # Allow relations when both objects originate from allowed connectors
        allowed_dbs = {
            self.default_db,
            self.admin_db,
            self.replica_db,
            self.admin_replica_db,
        }
        if {obj1._state.db, obj2._state.db} <= allowed_dbs:
            return True
        return None


READ_REPLICA_ALIAS = (
    MainRouter.replica_db if MainRouter.replica_db in settings.DATABASES else None
)
