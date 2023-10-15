################## Account
from typing import Optional

from pydantic import BaseModel

from prowler.providers.aws.lib.service.service import AWSService


class Account(AWSService):
    def __init__(self, audit_info):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, audit_info)
        self.__get_contacts__()

    def __get_contacts__(self):
        try:
            self.contacts = Contacts(
                base=self.client.get_contact_information()["ContactInformation"],
                billing=self.client.get_alternate_contact(
                    AlternateContactType="BILLING"
                ),
                security=self.client.get_alternate_contact(
                    AlternateContactType="SECURITY"
                ),
                operations=self.client.get_alternate_contact(
                    AlternateContactType="OPERATIONS"
                ),
            )
        except Exception:
            self.contacts = Contacts()


class Contacts(BaseModel):
    base: Optional[str]
    billing: Optional[str]
    security: Optional[str]
    operations: Optional[str]

    def get_contacts_list(self):
        return [self.base, self.billing, self.security, self.operations]


### This service don't need boto3 calls
