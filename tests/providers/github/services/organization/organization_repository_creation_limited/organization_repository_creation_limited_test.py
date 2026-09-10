from unittest import mock

from prowler.lib.check.models import Severity
from prowler.providers.github.services.organization.organization_service import Org
from tests.providers.github.github_fixtures import set_mocked_github_provider


class Test_organization_repository_creation_limited:
    def test_no_organizations(self):
        organization_client = mock.MagicMock
        organization_client.organizations = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited import (
                organization_repository_creation_limited,
            )

            check = organization_repository_creation_limited()
            result = check.execute()
            assert len(result) == 0

    def test_repository_creation_disabled_globally(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=None,
                members_can_create_repositories=False,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited import (
                organization_repository_creation_limited,
            )

            check = organization_repository_creation_limited()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_name == org_name
            assert result[0].status == "PASS"
            assert result[0].check_metadata.Severity == Severity.high
            assert (
                result[0].status_extended
                == f"Organization {org_name} has disabled repository creation for members."
            )

    def test_repository_creation_allowed_for_members(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=None,
                members_can_create_repositories=True,
                members_can_create_public_repositories=True,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited import (
                organization_repository_creation_limited,
            )

            check = organization_repository_creation_limited()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].check_metadata.Severity == Severity.high
            assert "public repositories" in result[0].status_extended
            assert "repositories of any type" in result[0].status_extended

    def test_repository_creation_disabled_per_visibility(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=None,
                members_can_create_public_repositories=False,
                members_can_create_private_repositories=False,
                members_can_create_internal_repositories=False,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited import (
                organization_repository_creation_limited,
            )

            check = organization_repository_creation_limited()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].check_metadata.Severity == Severity.high
            assert (
                result[0].status_extended
                == f"Organization {org_name} has disabled repository creation for members."
            )

    def test_repository_creation_disabled_via_members_allowed_type(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=None,
                members_allowed_repository_creation_type="none",
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited import (
                organization_repository_creation_limited,
            )

            check = organization_repository_creation_limited()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].check_metadata.Severity == Severity.high
            assert (
                result[0].status_extended
                == f"Organization {org_name} has disabled repository creation for members."
            )

    def test_repository_creation_type_none_with_private_enabled(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=None,
                members_can_create_repositories=True,
                members_allowed_repository_creation_type="none",
                members_can_create_private_repositories=True,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited import (
                organization_repository_creation_limited,
            )

            check = organization_repository_creation_limited()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].check_metadata.Severity == Severity.low
            assert "repositories of any type" not in result[0].status_extended
            assert "private repositories" in result[0].status_extended
            assert (
                "Public repository creation is disabled." in result[0].status_extended
            )

    def test_repository_creation_public_flag_only(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=None,
                members_can_create_public_repositories=True,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited import (
                organization_repository_creation_limited,
            )

            check = organization_repository_creation_limited()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].check_metadata.Severity == Severity.high

    def test_repository_creation_private_only(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=None,
                members_can_create_repositories=True,
                members_can_create_public_repositories=False,
                members_can_create_private_repositories=True,
                members_can_create_internal_repositories=False,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited import (
                organization_repository_creation_limited,
            )

            check = organization_repository_creation_limited()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].check_metadata.Severity == Severity.low
            assert (
                "Public repository creation is disabled." in result[0].status_extended
            )
            assert "repositories of any type" not in result[0].status_extended

    def test_repository_creation_public_flag_unknown_is_not_downgraded(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=None,
                members_can_create_private_repositories=True,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited import (
                organization_repository_creation_limited,
            )

            check = organization_repository_creation_limited()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].check_metadata.Severity == Severity.high
            assert (
                "Public repository creation is disabled."
                not in result[0].status_extended
            )

    def test_repository_creation_internal_only(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=None,
                members_can_create_public_repositories=False,
                members_can_create_private_repositories=False,
                members_can_create_internal_repositories=True,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited import (
                organization_repository_creation_limited,
            )

            check = organization_repository_creation_limited()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].check_metadata.Severity == Severity.low
            assert (
                "Public repository creation is disabled." in result[0].status_extended
            )

    def test_repository_creation_private_and_internal(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=None,
                members_can_create_public_repositories=False,
                members_can_create_private_repositories=True,
                members_can_create_internal_repositories=True,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited import (
                organization_repository_creation_limited,
            )

            check = organization_repository_creation_limited()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].check_metadata.Severity == Severity.low
            assert (
                "Public repository creation is disabled." in result[0].status_extended
            )

    def test_repository_creation_type_all(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=None,
                members_allowed_repository_creation_type="all",
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited import (
                organization_repository_creation_limited,
            )

            check = organization_repository_creation_limited()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].check_metadata.Severity == Severity.high

    def test_repository_creation_type_private(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=None,
                members_allowed_repository_creation_type="private",
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited import (
                organization_repository_creation_limited,
            )

            check = organization_repository_creation_limited()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].check_metadata.Severity == Severity.low
            assert (
                "Public repository creation is disabled." in result[0].status_extended
            )

    def test_repository_creation_type_selected_is_undeterminable(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=None,
                members_allowed_repository_creation_type="selected",
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited import (
                organization_repository_creation_limited,
            )

            check = organization_repository_creation_limited()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].check_metadata.Severity == Severity.high

    def test_repository_creation_global_flag_only(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=None,
                members_can_create_repositories=True,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited import (
                organization_repository_creation_limited,
            )

            check = organization_repository_creation_limited()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].check_metadata.Severity == Severity.high

    def test_repository_creation_severity_does_not_leak_between_organizations(self):
        organization_client = mock.MagicMock
        public_org_name = "public-organization"
        private_org_name = "private-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=public_org_name,
                mfa_required=None,
                members_can_create_public_repositories=True,
            ),
            2: Org(
                id=2,
                name=private_org_name,
                mfa_required=None,
                members_can_create_public_repositories=False,
                members_can_create_private_repositories=True,
                members_can_create_internal_repositories=False,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited import (
                organization_repository_creation_limited,
            )

            check = organization_repository_creation_limited()
            result = check.execute()
            assert len(result) == 2

            results_by_name = {r.resource_name: r for r in result}
            assert results_by_name[public_org_name].status == "FAIL"
            assert (
                results_by_name[public_org_name].check_metadata.Severity
                == Severity.high
            )
            assert results_by_name[private_org_name].status == "FAIL"
            assert (
                results_by_name[private_org_name].check_metadata.Severity
                == Severity.low
            )
