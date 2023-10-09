################## Account
from prowler.providers.aws.lib.service.service import AWSService


class Account(AWSService):
    def __init__(self, audit_info):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, audit_info)
        self.contacts = []
        self.__get_contacts__()

    def __get_contacts__(self):
        self.contacts.append(
            self.client.get_contact_information()["ContactInformation"]
        )
        try:
            self.contacts.append(
                self.client.get_alternate_contact(AlternateContactType="BILLING")
            )
            self.contacts.append(
                self.client.get_alternate_contact(AlternateContactType="SECURITY")
            )
            self.contacts.append(
                self.client.get_alternate_contact(AlternateContactType="OPERATIONS")
            )
        except Exception:
            self.contacts.append(None)


### This service don't need boto3 calls
