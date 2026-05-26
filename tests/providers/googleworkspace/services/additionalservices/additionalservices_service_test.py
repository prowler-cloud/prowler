from unittest.mock import MagicMock, patch

from tests.providers.googleworkspace.googleworkspace_fixtures import (
    set_mocked_googleworkspace_provider,
)


class TestAdditionalServicesService:
    def test_fetch_policies_groups_off(self):
        """Test fetching Additional Services policy with Groups OFF"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_credentials = MagicMock()
        mock_session = MagicMock()
        mock_session.credentials = mock_credentials
        mock_provider.session = mock_session

        mock_service = MagicMock()
        mock_policies_list = MagicMock()
        mock_policies_list.execute.return_value = {
            "policies": [
                {
                    "setting": {
                        "type": "settings/groups.service_status",
                        "value": {
                            "serviceState": "DISABLED",
                        },
                    }
                },
            ]
        }
        mock_service.policies().list.return_value = mock_policies_list
        mock_service.policies().list_next.return_value = None

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.additionalservices.additionalservices_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.additionalservices.additionalservices_service import (
                AdditionalServices,
            )

            additional_services = AdditionalServices(mock_provider)

            assert additional_services.policies_fetched is True
            assert additional_services.policies.groups_service_state == "DISABLED"

    def test_fetch_policies_groups_on(self):
        """Test fetching Additional Services policy with Groups ON"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        mock_service = MagicMock()
        mock_policies_list = MagicMock()
        mock_policies_list.execute.return_value = {
            "policies": [
                {
                    "setting": {
                        "type": "settings/groups.service_status",
                        "value": {
                            "serviceState": "ENABLED",
                        },
                    }
                },
            ]
        }
        mock_service.policies().list.return_value = mock_policies_list
        mock_service.policies().list_next.return_value = None

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.additionalservices.additionalservices_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.additionalservices.additionalservices_service import (
                AdditionalServices,
            )

            additional_services = AdditionalServices(mock_provider)

            assert additional_services.policies_fetched is True
            assert additional_services.policies.groups_service_state == "ENABLED"

    def test_fetch_policies_empty_response(self):
        """Test handling empty policies response"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        mock_service = MagicMock()
        mock_policies_list = MagicMock()
        mock_policies_list.execute.return_value = {"policies": []}
        mock_service.policies().list.return_value = mock_policies_list
        mock_service.policies().list_next.return_value = None

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.additionalservices.additionalservices_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.additionalservices.additionalservices_service import (
                AdditionalServices,
            )

            additional_services = AdditionalServices(mock_provider)

            assert additional_services.policies_fetched is True
            assert additional_services.policies.groups_service_state is None

    def test_fetch_policies_api_error(self):
        """Test handling of API errors during policy fetch"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        mock_service = MagicMock()
        mock_service.policies().list.side_effect = Exception("API Error")

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.additionalservices.additionalservices_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.additionalservices.additionalservices_service import (
                AdditionalServices,
            )

            additional_services = AdditionalServices(mock_provider)

            assert additional_services.policies_fetched is False
            assert additional_services.policies.groups_service_state is None

    def test_fetch_policies_build_service_returns_none(self):
        """Test early return when _build_service fails to construct the client"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.additionalservices.additionalservices_service.GoogleWorkspaceService._build_service",
                return_value=None,
            ),
        ):
            from prowler.providers.googleworkspace.services.additionalservices.additionalservices_service import (
                AdditionalServices,
            )

            additional_services = AdditionalServices(mock_provider)

            assert additional_services.policies_fetched is False
            assert additional_services.policies.groups_service_state is None

    def test_fetch_policies_execute_raises(self):
        """Test inner except handler when request.execute() raises during pagination"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        mock_service = MagicMock()
        mock_request = MagicMock()
        mock_request.execute.side_effect = Exception("Execute failed")
        mock_service.policies().list.return_value = mock_request

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.additionalservices.additionalservices_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.additionalservices.additionalservices_service import (
                AdditionalServices,
            )

            additional_services = AdditionalServices(mock_provider)

            assert additional_services.policies_fetched is False
            assert additional_services.policies.groups_service_state is None

    def test_additional_services_policies_model(self):
        """Test AdditionalServicesPolicies Pydantic model"""
        from prowler.providers.googleworkspace.services.additionalservices.additionalservices_service import (
            AdditionalServicesPolicies,
        )

        policies = AdditionalServicesPolicies(groups_service_state="DISABLED")

        assert policies.groups_service_state == "DISABLED"
