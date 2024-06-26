from unittest import mock

from prowler.providers.aws.services.account.account_service import Contact

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
AWS_REGION = "us-east-1"


class Test_account_maintain_different_contact_details_to_security_billing_and_operations:
    def test_contacts_not_configured_or_equal(self):
        account_client = mock.MagicMock
        account_client.region = AWS_REGION
        account_client.audited_account = AWS_ACCOUNT_NUMBER
        account_client.audited_account_arn = AWS_ACCOUNT_ARN

        # Account Contacts
        account_client.contact_base = Contact(type="PRIMARY")
        account_client.contacts_billing = Contact(type="BILLING")
        account_client.contacts_security = Contact(type="SECURITY")
        account_client.contacts_operations = Contact(type="OPERATIONS")

        # Account Sets
        account_client.number_of_contacts = 4
        account_client.contact_phone_numbers = {}
        account_client.contact_names = {}
        account_client.contact_emails = {}

        with mock.patch(
            "prowler.providers.aws.services.account.account_service.Account",
            new=account_client,
        ), mock.patch(
            "prowler.providers.aws.services.account.account_client.account_client",
            new=account_client,
        ):
            # Test Check
            from prowler.providers.aws.services.account.account_maintain_different_contact_details_to_security_billing_and_operations.account_maintain_different_contact_details_to_security_billing_and_operations import (
                account_maintain_different_contact_details_to_security_billing_and_operations,
            )

            check = (
                account_maintain_different_contact_details_to_security_billing_and_operations()
            )
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "SECURITY, BILLING and OPERATIONS contacts not found or they are not different between each other and between ROOT contact."
            )
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == AWS_ACCOUNT_ARN

    def test_contacts_diffent(self):
        account_client = mock.MagicMock
        account_client.region = AWS_REGION
        account_client.audited_account = AWS_ACCOUNT_NUMBER
        account_client.audited_account_arn = AWS_ACCOUNT_ARN

        # Account Contacts
        account_client.contact_base = Contact(type="PRIMARY")
        account_client.contacts_billing = Contact(type="BILLING")
        account_client.contacts_security = Contact(type="SECURITY")
        account_client.contacts_operations = Contact(type="OPERATIONS")

        # Account Sets
        account_client.number_of_contacts = 4
        account_client.contact_phone_numbers = {"666", "777", "888", "999"}
        account_client.contact_names = {"A", "B", "C", "D"}
        account_client.contact_emails = {
            "test1@test.com",
            "test2@test.com",
            "test3@test.com",
        }

        with mock.patch(
            "prowler.providers.aws.services.account.account_service.Account",
            new=account_client,
        ), mock.patch(
            "prowler.providers.aws.services.account.account_client.account_client",
            new=account_client,
        ):
            # Test Check
            from prowler.providers.aws.services.account.account_maintain_different_contact_details_to_security_billing_and_operations.account_maintain_different_contact_details_to_security_billing_and_operations import (
                account_maintain_different_contact_details_to_security_billing_and_operations,
            )

            check = (
                account_maintain_different_contact_details_to_security_billing_and_operations()
            )
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "SECURITY, BILLING and OPERATIONS contacts found and they are different between each other and between ROOT contact."
            )
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == AWS_ACCOUNT_ARN

    def test_access_denied(self):
        account_client = mock.MagicMock
        account_client.region = AWS_REGION
        account_client.audited_account = AWS_ACCOUNT_NUMBER
        account_client.audited_account_arn = AWS_ACCOUNT_ARN
        account_client.contact_base = None

        with mock.patch(
            "prowler.providers.aws.services.account.account_service.Account",
            new=account_client,
        ), mock.patch(
            "prowler.providers.aws.services.account.account_client.account_client",
            new=account_client,
        ):
            # Test Check
            from prowler.providers.aws.services.account.account_maintain_different_contact_details_to_security_billing_and_operations.account_maintain_different_contact_details_to_security_billing_and_operations import (
                account_maintain_different_contact_details_to_security_billing_and_operations,
            )

            check = (
                account_maintain_different_contact_details_to_security_billing_and_operations()
            )
            result = check.execute()

            assert len(result) == 0
