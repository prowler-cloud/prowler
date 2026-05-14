import asyncio
from types import SimpleNamespace
from unittest import mock
from unittest.mock import AsyncMock, patch

from prowler.providers.m365.services.intune.intune_service import (
    Intune,
    IntuneCompliancePolicy,
    IntuneManagedDevice,
    IntuneSettings,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider

# --- Mock async helpers for patching Intune methods ---


async def mock_get_settings_with_secure_by_default(_):
    return IntuneSettings(secure_by_default=True), None


async def mock_get_settings_null(_):
    return IntuneSettings(secure_by_default=None), None


async def mock_get_settings_error(_):
    return (
        None,
        "Could not read Microsoft Intune device management settings. Ensure the Service Principal has DeviceManagementServiceConfig.Read.All permission granted.",
    )


async def mock_get_compliance_policies_with_assignments(_):
    return [
        IntuneCompliancePolicy(
            id="policy-1", display_name="Windows Policy", assignment_count=2
        ),
        IntuneCompliancePolicy(
            id="policy-2", display_name="iOS Policy", assignment_count=0
        ),
    ], None


async def mock_get_compliance_policies_empty(_):
    return [], None


async def mock_get_compliance_policies_error(_):
    return (
        None,
        "Could not read Microsoft Intune device compliance policies. Ensure the Service Principal has DeviceManagementConfiguration.Read.All permission granted.",
    )


async def mock_get_managed_devices_with_compliant(_):
    return [
        IntuneManagedDevice(
            id="device-1",
            device_name="Laptop-1",
            compliance_state="compliant",
            management_agent="mdm",
        ),
    ], None


async def mock_get_managed_devices_empty(_):
    return [], None


async def mock_get_managed_devices_error(_):
    return (
        None,
        "Could not read Microsoft Intune managed devices. Ensure the Service Principal has DeviceManagementManagedDevices.Read.All permission granted.",
    )


def _build_intune_service(
    get_settings_mock=mock_get_settings_with_secure_by_default,
    get_compliance_policies_mock=mock_get_compliance_policies_with_assignments,
    get_managed_devices_mock=mock_get_managed_devices_with_compliant,
):
    """Instantiate Intune with patched async methods."""
    with (
        patch(
            "prowler.providers.m365.services.intune.intune_service.Intune._get_settings",
            new=get_settings_mock,
        ),
        patch(
            "prowler.providers.m365.services.intune.intune_service.Intune._get_compliance_policies",
            new=get_compliance_policies_mock,
        ),
        patch(
            "prowler.providers.m365.services.intune.intune_service.Intune._get_managed_devices",
            new=get_managed_devices_mock,
        ),
    ):
        return Intune(set_mocked_m365_provider())


class Test_Intune_Service:
    def test_get_settings_secure_by_default_true(self):
        intune = _build_intune_service()
        assert intune.settings is not None
        assert intune.settings.secure_by_default is True
        assert intune.verification_error is None

    def test_get_settings_null(self):
        intune = _build_intune_service(
            get_settings_mock=mock_get_settings_null,
        )
        assert intune.settings is not None
        assert intune.settings.secure_by_default is None
        assert intune.verification_error is None

    def test_get_settings_error(self):
        intune = _build_intune_service(
            get_settings_mock=mock_get_settings_error,
        )
        assert intune.settings is None
        assert intune.verification_error is not None
        assert "DeviceManagementServiceConfig.Read.All" in intune.verification_error

    def test_get_compliance_policies(self):
        intune = _build_intune_service()
        assert intune.compliance_policies is not None
        assert len(intune.compliance_policies) == 2
        assert intune.compliance_policies[0].id == "policy-1"
        assert intune.compliance_policies[0].display_name == "Windows Policy"
        assert intune.compliance_policies[0].assignment_count == 2
        assert intune.compliance_policies[1].assignment_count == 0

    def test_get_compliance_policies_empty(self):
        intune = _build_intune_service(
            get_compliance_policies_mock=mock_get_compliance_policies_empty,
        )
        assert intune.compliance_policies == []
        assert intune.verification_error is None

    def test_get_compliance_policies_error(self):
        intune = _build_intune_service(
            get_compliance_policies_mock=mock_get_compliance_policies_error,
        )
        assert intune.compliance_policies is None
        assert intune.verification_error is not None
        assert "DeviceManagementConfiguration.Read.All" in intune.verification_error

    def test_get_managed_devices(self):
        intune = _build_intune_service()
        assert intune.managed_devices is not None
        assert len(intune.managed_devices) == 1
        assert intune.managed_devices[0].id == "device-1"
        assert intune.managed_devices[0].device_name == "Laptop-1"
        assert intune.managed_devices[0].compliance_state == "compliant"
        assert intune.managed_devices[0].management_agent == "mdm"

    def test_get_managed_devices_empty(self):
        intune = _build_intune_service(
            get_managed_devices_mock=mock_get_managed_devices_empty,
        )
        assert intune.managed_devices == []
        assert intune.verification_error is None

    def test_get_managed_devices_error(self):
        intune = _build_intune_service(
            get_managed_devices_mock=mock_get_managed_devices_error,
        )
        assert intune.managed_devices is None
        assert intune.verification_error is not None
        assert "DeviceManagementManagedDevices.Read.All" in intune.verification_error

    def test_multiple_errors_concatenated(self):
        intune = _build_intune_service(
            get_settings_mock=mock_get_settings_error,
            get_compliance_policies_mock=mock_get_compliance_policies_error,
        )
        assert intune.verification_error is not None
        assert "DeviceManagementServiceConfig.Read.All" in intune.verification_error
        assert "DeviceManagementConfiguration.Read.All" in intune.verification_error

    def test_is_mdm_managed_device_true(self):
        for agent in [
            "mdm",
            "easMdm",
            "intuneClient",
            "easIntuneClient",
            "configurationManagerClientMdm",
            "configurationManagerClientMdmEas",
            "microsoft365ManagedMdm",
        ]:
            assert Intune.is_mdm_managed_device(agent) is True

    def test_is_mdm_managed_device_false(self):
        for agent in ["eas", "googleCloudDevicePolicyController", "", "unknown"]:
            assert Intune.is_mdm_managed_device(agent) is False


def test_intune_get_compliance_policies_pagination():
    """Test that _get_compliance_policies handles pagination correctly."""
    intune = Intune.__new__(Intune)

    policy_page_one = [
        SimpleNamespace(id="policy-1", display_name="Policy 1"),
    ]
    policy_page_two = [
        SimpleNamespace(id="policy-2", display_name="Policy 2"),
    ]

    response_page_one = SimpleNamespace(
        value=policy_page_one,
        odata_next_link="next-link",
    )
    response_page_two = SimpleNamespace(
        value=policy_page_two,
        odata_next_link=None,
    )

    assignments_response = SimpleNamespace(
        value=[SimpleNamespace()],
        odata_next_link=None,
    )

    mock_client = mock.MagicMock()
    mock_policies = mock_client.device_management.device_compliance_policies

    mock_policies.get = AsyncMock(return_value=response_page_one)
    mock_policies.with_url.return_value.get = AsyncMock(return_value=response_page_two)
    mock_policies.by_device_compliance_policy_id.return_value.assignments.get = (
        AsyncMock(return_value=assignments_response)
    )

    intune.client = mock_client

    loop = asyncio.new_event_loop()
    try:
        policies, error = loop.run_until_complete(intune._get_compliance_policies())
    finally:
        loop.close()

    assert error is None
    assert len(policies) == 2
    assert policies[0].id == "policy-1"
    assert policies[1].id == "policy-2"
    assert policies[0].assignment_count == 1
    assert policies[1].assignment_count == 1


def test_intune_get_managed_devices_pagination():
    """Test that _get_managed_devices handles pagination correctly."""
    intune = Intune.__new__(Intune)

    device_page_one = [
        SimpleNamespace(
            id="device-1",
            device_name="Laptop-1",
            compliance_state="compliant",
            management_agent="mdm",
        ),
    ]
    device_page_two = [
        SimpleNamespace(
            id="device-2",
            device_name="Laptop-2",
            compliance_state="noncompliant",
            management_agent="eas",
        ),
    ]

    response_page_one = SimpleNamespace(
        value=device_page_one,
        odata_next_link="next-link",
    )
    response_page_two = SimpleNamespace(
        value=device_page_two,
        odata_next_link=None,
    )

    mock_client = mock.MagicMock()
    mock_managed_devices = mock_client.device_management.managed_devices

    mock_managed_devices.get = AsyncMock(return_value=response_page_one)
    mock_managed_devices.with_url.return_value.get = AsyncMock(
        return_value=response_page_two
    )

    intune.client = mock_client

    loop = asyncio.new_event_loop()
    try:
        devices, error = loop.run_until_complete(intune._get_managed_devices())
    finally:
        loop.close()

    assert error is None
    assert len(devices) == 2
    assert devices[0].id == "device-1"
    assert devices[0].compliance_state == "compliant"
    assert devices[0].management_agent == "mdm"
    assert devices[1].id == "device-2"
    assert devices[1].compliance_state == "noncompliant"
    assert devices[1].management_agent == "eas"


def test_intune_get_settings_with_secure_by_default():
    """Test _get_settings when Graph returns settings with secure_by_default."""
    intune = Intune.__new__(Intune)

    device_management_response = SimpleNamespace(
        settings=SimpleNamespace(secure_by_default=True)
    )

    mock_client = mock.MagicMock()
    mock_client.device_management.get = AsyncMock(
        return_value=device_management_response
    )

    intune.client = mock_client

    loop = asyncio.new_event_loop()
    try:
        settings, error = loop.run_until_complete(intune._get_settings())
    finally:
        loop.close()

    assert error is None
    assert settings is not None
    assert settings.secure_by_default is True


def test_intune_get_settings_null_settings():
    """Test _get_settings when Graph returns settings = None."""
    intune = Intune.__new__(Intune)

    device_management_response = SimpleNamespace(settings=None)

    mock_client = mock.MagicMock()
    mock_client.device_management.get = AsyncMock(
        return_value=device_management_response
    )

    intune.client = mock_client

    loop = asyncio.new_event_loop()
    try:
        settings, error = loop.run_until_complete(intune._get_settings())
    finally:
        loop.close()

    assert error is None
    assert settings is not None
    assert settings.secure_by_default is None


def test_intune_get_settings_retries_without_select_when_settings_missing():
    """Test _get_settings retries without $select when settings are omitted."""
    intune = Intune.__new__(Intune)

    selected_response = SimpleNamespace(settings=None)
    full_response = SimpleNamespace(settings=SimpleNamespace(secure_by_default=True))

    mock_client = mock.MagicMock()
    mock_client.device_management.get = AsyncMock(
        side_effect=[selected_response, full_response]
    )

    intune.client = mock_client

    loop = asyncio.new_event_loop()
    try:
        settings, error = loop.run_until_complete(intune._get_settings())
    finally:
        loop.close()

    assert error is None
    assert settings is not None
    assert settings.secure_by_default is True
    assert mock_client.device_management.get.await_count == 2


def test_intune_get_settings_retries_without_select_when_value_missing():
    """Test _get_settings retries without $select when secure_by_default is omitted."""
    intune = Intune.__new__(Intune)

    selected_response = SimpleNamespace(
        settings=SimpleNamespace(secure_by_default=None)
    )
    full_response = SimpleNamespace(settings=SimpleNamespace(secure_by_default=False))

    mock_client = mock.MagicMock()
    mock_client.device_management.get = AsyncMock(
        side_effect=[selected_response, full_response]
    )

    intune.client = mock_client

    loop = asyncio.new_event_loop()
    try:
        settings, error = loop.run_until_complete(intune._get_settings())
    finally:
        loop.close()

    assert error is None
    assert settings is not None
    assert settings.secure_by_default is False
    assert mock_client.device_management.get.await_count == 2


def test_intune_get_settings_exception():
    """Test _get_settings handles exceptions gracefully."""
    intune = Intune.__new__(Intune)

    mock_client = mock.MagicMock()
    mock_client.device_management.get = AsyncMock(side_effect=Exception("API Error"))

    intune.client = mock_client

    loop = asyncio.new_event_loop()
    try:
        settings, error = loop.run_until_complete(intune._get_settings())
    finally:
        loop.close()

    assert settings is None
    assert error is not None
    assert "DeviceManagementServiceConfig.Read.All" in error
