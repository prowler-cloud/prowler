from re import search
from unittest import mock

from prowler.providers.gcp.services.iam.iam_service import Organization

GCP_PROJECT_ID = "123456789012"


class Test_iam_organization_essential_contacts_configured:
    def test_iam_no_organizations(self):
        essentialcontacts_client = mock.MagicMock
        essentialcontacts_client.organizations = []
        essentialcontacts_client.region = "global"

        with mock.patch(
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
        essentialcontacts_client = mock.MagicMock
        essentialcontacts_client.organizations = [
            Organization(id="test_id", name="test", contacts=True)
        ]
        essentialcontacts_client.region = "global"

        with mock.patch(
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
        essentialcontacts_client = mock.MagicMock
        essentialcontacts_client.organizations = [
            Organization(id="test_id", name="test", contacts=False)
        ]
        essentialcontacts_client.region = "global"

        with mock.patch(
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
