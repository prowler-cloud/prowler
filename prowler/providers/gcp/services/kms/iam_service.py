from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.gcp_provider import generate_client


################## IAM
class IAM:
    def __init__(self, audit_info):
        self.service = "iam"
        self.api_version = "v1"
        self.project_id = audit_info.project_id
        self.region = "global"
        self.client = generate_client(self.service, self.api_version, audit_info)
        self.service_accounts = []
        self.__get_service_accounts__()

    def __get_client__(self):
        return self.client

    def __get_service_accounts__(self):
        try:
            request = (
                self.client.projects()
                .serviceAccounts()
                .list(name="projects/" + self.project_id)
            )
            while request is not None:
                response = request.execute()

                for account in response["accounts"]:
                    self.service_accounts.append(
                        ServiceAccount(
                            name=account["name"],
                            email=account["email"],
                            display_name=account["displayName"],
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


class ServiceAccount(BaseModel):
    name: str
    email: str
    display_name: str
