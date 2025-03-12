from unittest.mock import patch

import pytest
from config.django.base import DATABASE_ROUTERS as PROD_DATABASE_ROUTERS
from django.conf import settings
from django.db.migrations.recorder import MigrationRecorder
from django.db.utils import ConnectionRouter

from api.db_router import MainRouter
from api.rls import Tenant


@patch("api.db_router.MainRouter.admin_db", new="admin")
@patch("api.db_router.MainRouter.admin_read", new="admin_read")
class TestMainDatabaseRouter:
    @pytest.fixture(scope="module")
    def router(self):
        testing_routers = settings.DATABASE_ROUTERS.copy()
        settings.DATABASE_ROUTERS = PROD_DATABASE_ROUTERS
        yield ConnectionRouter()
        settings.DATABASE_ROUTERS = testing_routers

    @pytest.mark.parametrize("api_model", [Tenant])
    def test_router_api_models(self, api_model, router):
        assert router.db_for_read(api_model) == "prowler_user_read"
        assert router.db_for_write(api_model) == "default"

        assert router.allow_migrate_model(MainRouter.admin_db, api_model)
        assert not router.allow_migrate_model("default", api_model)

    def test_router_django_models(self, router):
        assert router.db_for_read(MigrationRecorder.Migration) == MainRouter.admin_read
        assert router.db_for_read(MigrationRecorder.Migration) != "default"
