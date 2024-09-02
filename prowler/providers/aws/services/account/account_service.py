################## Account
from typing import Optional
from venv import logger

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.providers.aws.lib.service.service import AWSService


class Account(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.number_of_contacts = 4
        self.contact_base = self._get_contact_information()
        self.contacts_billing = self._get_alternate_contact("BILLING")
        self.contacts_security = self._get_alternate_contact("SECURITY")
        self.contacts_operations = self._get_alternate_contact("OPERATIONS")

        if self.contact_base:
            # Set of contact phone numbers
            self.contact_phone_numbers = {
                self.contact_base.phone_number,
                self.contacts_billing.phone_number,
                self.contacts_security.phone_number,
                self.contacts_operations.phone_number,
            }

            # Set of contact names
            self.contact_names = {
                self.contact_base.name,
                self.contacts_billing.name,
                self.contacts_security.name,
                self.contacts_operations.name,
            }

            # Set of contact emails
            self.contact_emails = {
                self.contacts_billing.email,
                self.contacts_security.email,
                self.contacts_operations.email,
            }

    def _get_contact_information(self):
        try:
            primary_account_contact = self.client.get_contact_information()[
                "ContactInformation"
            ]

            return Contact(
                type="PRIMARY",
                name=primary_account_contact.get("FullName"),
                phone_number=primary_account_contact.get("PhoneNumber"),
            )
        except Exception as error:
            if error.response["Error"]["Code"] == "AccessDeniedException":
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                return None
            else:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                return Contact(type="PRIMARY")

    def _get_alternate_contact(self, contact_type: str):
        try:
            account_contact = self.client.get_alternate_contact(
                AlternateContactType=contact_type
            )["AlternateContact"]

            return Contact(
                type=contact_type,
                email=account_contact.get("EmailAddress"),
                name=account_contact.get("Name"),
                phone_number=account_contact.get("PhoneNumber"),
            )

        except ClientError as error:
            if (
                error.response["Error"]["Code"] == "ResourceNotFoundException"
                and error.response["Error"]["Message"]
                == "No contact of the inputted alternate contact type found."
            ):
                logger.warning(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            return Contact(
                type=contact_type,
            )

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return Contact(
                type=contact_type,
            )


class Contact(BaseModel):
    type: str
    email: Optional[str]
    name: Optional[str]
    phone_number: Optional[str]
