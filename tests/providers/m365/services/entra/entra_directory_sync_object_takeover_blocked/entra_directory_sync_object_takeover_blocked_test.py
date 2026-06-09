import asyncio
import importlib
from types import SimpleNamespace
from unittest import mock
from unittest.mock import AsyncMock

import pytest

from prowler.providers.m365.services.entra.entra_service import (
    DirectorySyncSettings,
    Entra,
    Organization,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider


@pytest.fixture
def entra_client():
    client = mock.MagicMock()
    client.directory_sync_settings = []
    client.directory_sync_error = None
    client.organizations = []
    return client


class Test_entra_directory_sync_object_takeover_blocked:
    def run_check(self, entra_client):
        client_module = SimpleNamespace(entra_client=entra_client)
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch.dict(
                "sys.modules",
                {"prowler.providers.m365.services.entra.entra_client": client_module},
            ),
        ):
            check_module = importlib.import_module(
                "prowler.providers.m365.services.entra."
                "entra_directory_sync_object_takeover_blocked."
                "entra_directory_sync_object_takeover_blocked"
            )
            check_module.entra_client = entra_client

            return check_module.entra_directory_sync_object_takeover_blocked().execute()

    def test_both_takeover_paths_blocked(self, entra_client):
        entra_client.directory_sync_settings = [
            DirectorySyncSettings(
                id="sync-001",
                block_soft_match_enabled=True,
                block_cloud_object_takeover_through_hard_match_enabled=True,
            )
        ]

        result = self.run_check(entra_client)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "both soft and hard matching" in result[0].status_extended
        assert result[0].resource_id == "sync-001"

    @pytest.mark.parametrize(
        ("soft_match_blocked", "hard_match_blocked", "expected"),
        [
            (False, True, "soft match"),
            (True, False, "hard match"),
            (False, False, "soft match and hard match"),
        ],
    )
    def test_reports_unblocked_takeover_paths(
        self,
        entra_client,
        soft_match_blocked,
        hard_match_blocked,
        expected,
    ):
        entra_client.directory_sync_settings = [
            DirectorySyncSettings(
                id="sync-001",
                block_soft_match_enabled=soft_match_blocked,
                block_cloud_object_takeover_through_hard_match_enabled=hard_match_blocked,
            )
        ]

        result = self.run_check(entra_client)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert expected in result[0].status_extended

    def test_permission_error_is_manual_for_hybrid_tenant(self, entra_client):
        entra_client.directory_sync_error = (
            "Insufficient privileges to read directory sync settings"
        )
        entra_client.organizations = [
            Organization(
                id="org-001",
                name="Hybrid Tenant",
                on_premises_sync_enabled=True,
            )
        ]

        result = self.run_check(entra_client)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "Insufficient privileges" in result[0].status_extended

    def test_cloud_only_tenant_is_not_applicable(self, entra_client):
        entra_client.organizations = [
            Organization(
                id="org-001",
                name="Cloud Tenant",
                on_premises_sync_enabled=False,
            )
        ]

        result = self.run_check(entra_client)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "cloud-only" in result[0].status_extended

    def test_missing_settings_is_manual_for_hybrid_tenant(self, entra_client):
        entra_client.organizations = [
            Organization(
                id="org-001",
                name="Hybrid Tenant",
                on_premises_sync_enabled=True,
            )
        ]

        result = self.run_check(entra_client)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "no directory sync settings were returned" in result[0].status_extended


def test_directory_sync_service_loads_takeover_protection_flags():
    features = SimpleNamespace(
        password_sync_enabled=True,
        seamless_sso_enabled=False,
        block_soft_match_enabled=True,
        block_cloud_object_takeover_through_hard_match_enabled=True,
    )
    response = SimpleNamespace(
        value=[SimpleNamespace(id="sync-001", features=features)]
    )
    entra_service = Entra.__new__(Entra)
    entra_service.client = SimpleNamespace(
        directory=SimpleNamespace(
            on_premises_synchronization=SimpleNamespace(
                get=AsyncMock(return_value=response)
            )
        )
    )

    settings, error = asyncio.run(entra_service._get_directory_sync_settings())

    assert error is None
    assert len(settings) == 1
    assert settings[0].block_soft_match_enabled is True
    assert settings[0].block_cloud_object_takeover_through_hard_match_enabled is True
