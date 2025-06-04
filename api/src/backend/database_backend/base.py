import django.db
from django.db.backends.postgresql.base import (
    DatabaseWrapper as BuiltinPostgresDatabaseWrapper,
)
from psycopg2 import InterfaceError


class DatabaseWrapper(BuiltinPostgresDatabaseWrapper):
    def create_cursor(self, name=None):
        try:
            return super().create_cursor(name=name)
        except InterfaceError:
            django.db.close_old_connections()
            django.db.connection.connect()
            return super().create_cursor(name=name)
