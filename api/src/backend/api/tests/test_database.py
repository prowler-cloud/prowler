from unittest.mock import Mock, patch

import pytest
from api.db_router import (
    MainRouter,
    get_write_db_alias,
    reset_write_db_alias,
    set_write_db_alias,
    write_db_alias,
)
from api.rls import Tenant
from config.django.base import DATABASE_ROUTERS as PROD_DATABASE_ROUTERS
from django.conf import settings
from django.db.migrations.recorder import MigrationRecorder
from django.db.utils import ConnectionRouter


@patch("api.db_router.MainRouter.admin_db", new="admin")
class TestMainDatabaseRouter:
    @pytest.fixture(scope="module")
    def router(self):
        testing_routers = settings.DATABASE_ROUTERS.copy()
        settings.DATABASE_ROUTERS = PROD_DATABASE_ROUTERS
        yield ConnectionRouter()
        settings.DATABASE_ROUTERS = testing_routers

    @pytest.mark.parametrize("api_model", [Tenant])
    def test_router_api_models(self, api_model, router):
        assert router.db_for_read(api_model) == "default"
        assert router.db_for_write(api_model) == "default"

        assert router.allow_migrate_model(MainRouter.admin_db, api_model)
        assert not router.allow_migrate_model("default", api_model)

    def test_scoped_write_alias_routes_api_models(self, router):
        token = set_write_db_alias(MainRouter.admin_db)
        try:
            assert get_write_db_alias() == MainRouter.admin_db
            assert router.db_for_write(Tenant) == MainRouter.admin_db
        finally:
            reset_write_db_alias(token)

        assert get_write_db_alias() is None
        assert router.db_for_write(Tenant) == "default"

    def test_scoped_write_alias_restores_nested_context(self, router):
        outer_token = set_write_db_alias("outer")
        try:
            assert router.db_for_write(Tenant) == "outer"

            inner_token = set_write_db_alias(MainRouter.admin_db)
            try:
                assert router.db_for_write(Tenant) == MainRouter.admin_db
            finally:
                reset_write_db_alias(inner_token)

            assert router.db_for_write(Tenant) == "outer"
        finally:
            reset_write_db_alias(outer_token)

        assert get_write_db_alias() is None
        assert router.db_for_write(Tenant) == "default"

    def test_scoped_write_alias_does_not_override_admin_models(self, router):
        token = set_write_db_alias("other")
        try:
            assert (
                router.db_for_write(MigrationRecorder.Migration) == MainRouter.admin_db
            )
        finally:
            reset_write_db_alias(token)

        assert get_write_db_alias() is None

    def test_write_db_alias_context_manager_resets_after_error(self, router):
        fail = Mock(side_effect=RuntimeError("Simulated failure"))

        with pytest.raises(RuntimeError, match="Simulated failure"):
            with write_db_alias(MainRouter.admin_db):
                assert get_write_db_alias() == MainRouter.admin_db
                assert router.db_for_write(Tenant) == MainRouter.admin_db
                fail()

        fail.assert_called_once_with()
        assert get_write_db_alias() is None
        assert router.db_for_write(Tenant) == "default"

    def test_write_db_alias_context_manager_ignores_empty_alias(self, router):
        with write_db_alias(None):
            assert get_write_db_alias() is None
            assert router.db_for_write(Tenant) == "default"

        assert get_write_db_alias() is None

    def test_router_django_models(self, router):
        assert router.db_for_read(MigrationRecorder.Migration) == MainRouter.admin_db
        assert not router.db_for_read(MigrationRecorder.Migration) == "default"
