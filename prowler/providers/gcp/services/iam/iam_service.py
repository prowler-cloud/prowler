from datetime import datetime

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.lib.service.service import GCPService
from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_client import (
    cloudresourcemanager_client,
)


################## IAM
class IAM(GCPService):
    def __init__(self, audit_info):
        super().__init__(__class__.__name__, audit_info)
        self.service_accounts = []
        self.__get_service_accounts__()
        self.__get_service_accounts_keys__()

    def __get_service_accounts__(self):
        for project_id in self.project_ids:
            try:
                request = (
                    self.client.projects()
                    .serviceAccounts()
                    .list(name="projects/" + project_id)
                )
                while request is not None:
                    response = request.execute()

                    for account in response["accounts"]:
                        self.service_accounts.append(
                            ServiceAccount(
                                name=account["name"],
                                email=account["email"],
                                display_name=account.get("displayName", ""),
                                project_id=project_id,
                            )
                        )

                    request = (
                        self.client.projects()
                        .serviceAccounts()
                        .list_next(previous_request=request, previous_response=response)
                    )
            except Exception as error:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def __get_service_accounts_keys__(self):
        try:
            for sa in self.service_accounts:
                request = (
                    self.client.projects()
                    .serviceAccounts()
                    .keys()
                    .list(
                        name="projects/"
                        + sa.project_id
                        + "/serviceAccounts/"
                        + sa.email
                    )
                )
                response = request.execute()

                for key in response["keys"]:
                    sa.keys.append(
                        Key(
                            name=key["name"].split("/")[-1],
                            origin=key["keyOrigin"],
                            type=key["keyType"],
                            valid_after=datetime.strptime(
                                key["validAfterTime"], "%Y-%m-%dT%H:%M:%SZ"
                            ),
                            valid_before=datetime.strptime(
                                key["validBeforeTime"], "%Y-%m-%dT%H:%M:%SZ"
                            ),
                        )
                    )

        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Key(BaseModel):
    name: str
    origin: str
    type: str
    valid_after: datetime
    valid_before: datetime


class ServiceAccount(BaseModel):
    name: str
    email: str
    display_name: str
    keys: list[Key] = []
    project_id: str


################## AccessApproval
class AccessApproval(GCPService):
    def __init__(self, audit_info):
        super().__init__(__class__.__name__, audit_info)
        self.settings = {}
        self.__get_settings__()

    def __get_settings__(self):
        for project_id in self.project_ids:
            try:
                response = (
                    self.client.projects().getAccessApprovalSettings(
                        name=f"projects/{project_id}/accessApprovalSettings"
                    )
                ).execute()
                self.settings[project_id].append(
                    Setting(
                        name=response["name"],
                        project_id=project_id,
                    )
                )
            except Exception as error:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class Setting(BaseModel):
    name: str
    project_id: str


################## EssentialContacts
class EssentialContacts(GCPService):
    def __init__(self, audit_info):
        super().__init__(__class__.__name__, audit_info)
        self.organizations = []
        self.__get_contacts__()

    def __get_contacts__(self):
        for org in cloudresourcemanager_client.organizations:
            try:
                contacts = False
                response = (
                    self.client.organizations()
                    .contacts()
                    .list(parent="organizations/" + org.id)
                ).execute()
                if len(response["contacts"]) > 0:
                    contacts = True

                self.organizations.append(
                    Organization(
                        name=org.name,
                        email=org.id,
                        contacts=contacts,
                    )
                )
            except Exception as error:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class Organization(BaseModel):
    name: str
    id: str
    contacts: bool
