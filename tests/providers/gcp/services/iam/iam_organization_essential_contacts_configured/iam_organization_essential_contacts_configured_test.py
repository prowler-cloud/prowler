from re import search
from unittest import mock

from tests.providers.gcp.gcp_fixtures import set_mocked_gcp_provider


class Test_iam_organization_essential_contacts_configured:
    def test_iam_no_organizations(self):
        essentialcontacts_client = mock.MagicMock
        essentialcontacts_client.organizations = []
        essentialcontacts_client.region = "global"

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_organization_essential_contacts_configured.iam_organization_essential_contacts_configured.essentialcontacts_client",
            new=essentialcontacts_client,
        ):
            from prowler.providers.gcp.services.iam.iam_organization_essential_contacts_configured.iam_organization_essential_contacts_configured import (
                iam_organization_essential_contacts_configured,
            )

            check = iam_organization_essential_contacts_configured()
            result = check.execute()
            assert len(result) == 0

    def test_iam_org_with_contacts(self):
        from prowler.providers.gcp.services.iam.iam_service import Organization

        essentialcontacts_client = mock.MagicMock
        essentialcontacts_client.organizations = [
            Organization(id="test_id", name="test", contacts=True)
        ]
        essentialcontacts_client.region = "global"

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_organization_essential_contacts_configured.iam_organization_essential_contacts_configured.essentialcontacts_client",
            new=essentialcontacts_client,
        ):
            from prowler.providers.gcp.services.iam.iam_organization_essential_contacts_configured.iam_organization_essential_contacts_configured import (
                iam_organization_essential_contacts_configured,
            )

            check = iam_organization_essential_contacts_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "has essential contacts configured",
                result[0].status_extended,
            )
            assert result[0].resource_id == "test_id"
            assert result[0].resource_name == "test"
            assert result[0].project_id == "test_id"
            assert result[0].location == "global"

    def test_iam_org_without_contacts(self):
        from prowler.providers.gcp.services.iam.iam_service import Organization

        essentialcontacts_client = mock.MagicMock
        essentialcontacts_client.organizations = [
            Organization(id="test_id", name="test", contacts=False)
        ]
        essentialcontacts_client.region = "global"

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_organization_essential_contacts_configured.iam_organization_essential_contacts_configured.essentialcontacts_client",
            new=essentialcontacts_client,
        ):
            from prowler.providers.gcp.services.iam.iam_organization_essential_contacts_configured.iam_organization_essential_contacts_configured import (
                iam_organization_essential_contacts_configured,
            )

            check = iam_organization_essential_contacts_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "does not have essential contacts configured",
                result[0].status_extended,
            )
            assert result[0].resource_id == "test_id"
            assert result[0].resource_name == "test"
            assert result[0].project_id == "test_id"
            assert result[0].location == "global"
