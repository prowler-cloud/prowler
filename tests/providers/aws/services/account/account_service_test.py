import botocore
from mock import patch

from prowler.providers.aws.services.account.account_service import Account, Contact
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    set_mocked_aws_audit_info,
)

# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwargs):
    """
    As you can see the operation_name has the list_analyzers snake_case form but
    we are using the ListAnalyzers form.
    Rationale -> https://github.com/boto/botocore/blob/develop/botocore/client.py#L810:L816

    We have to mock every AWS API call using Boto3
    """
    if operation_name == "GetContactInformation":
        return {
            "ContactInformation": {
                "AddressLine1": "AddressLine1",
                "AddressLine2": "AddressLine2",
                "AddressLine3": "AddressLine3",
                "City": "City",
                "CompanyName": "Prowler",
                "CountryCode": "CountryCode",
                "DistrictOrCounty": "DistrictOrCounty",
                "FullName": "Prowler",
                "PhoneNumber": "666666666",
                "PostalCode": "PostalCode",
                "StateOrRegion": "StateOrRegion",
                "WebsiteUrl": "WebsiteUrl",
            }
        }
    if operation_name == "GetAlternateContact":
        return {
            "AlternateContact": {
                "AlternateContactType": "SECURITY",
                "EmailAddress": "test@test.com",
                "Name": "Prowler",
                "PhoneNumber": "666666666",
                "Title": "Title",
            }
        }

    return make_api_call(self, operation_name, kwargs)


# Patch every AWS call using Boto3
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_Account_Service:
    # Test Account Service
    def test_service(self):
        audit_info = set_mocked_aws_audit_info()
        account = Account(audit_info)
        assert account.service == "account"

    # Test Account Client
    def test_client(self):
        audit_info = set_mocked_aws_audit_info()
        account = Account(audit_info)
        assert account.client.__class__.__name__ == "Account"

    # Test Account Session
    def test__get_session__(self):
        audit_info = set_mocked_aws_audit_info()
        account = Account(audit_info)
        assert account.session.__class__.__name__ == "Session"

    # Test Account Session
    def test_audited_account(self):
        audit_info = set_mocked_aws_audit_info()
        account = Account(audit_info)
        assert account.audited_account == AWS_ACCOUNT_NUMBER

    # Test Account Get Account Contacts
    def test_get_account_contacts(self):
        # Account client for this test class
        audit_info = set_mocked_aws_audit_info()
        account = Account(audit_info)
        assert account.number_of_contacts == 4
        assert account.contact_base == Contact(
            type="PRIMARY",
            name="Prowler",
            phone_number="666666666",
        )
        assert account.contacts_billing == Contact(
            type="BILLING",
            email="test@test.com",
            name="Prowler",
            phone_number="666666666",
        )
        assert account.contacts_security == Contact(
            type="SECURITY",
            email="test@test.com",
            name="Prowler",
            phone_number="666666666",
        )
        assert account.contacts_operations == Contact(
            type="OPERATIONS",
            email="test@test.com",
            name="Prowler",
            phone_number="666666666",
        )
