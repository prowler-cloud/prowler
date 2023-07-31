from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.lib.service.service import GCPService


################## API Keys
class APIKeys(GCPService):
    def __init__(self, audit_info):
        super().__init__(__class__.__name__, audit_info, api_version="v2")

        self.keys = []
        self.__get_keys__()

    def __get_keys__(self):
        for project_id in self.project_ids:
            try:
                request = (
                    self.client.projects()
                    .locations()
                    .keys()
                    .list(
                        parent=f"projects/{project_id}/locations/global",
                    )
                )
                while request is not None:
                    response = request.execute()

                    for key in response.get("keys", []):
                        self.keys.append(
                            Key(
                                name=key["displayName"],
                                id=key["uid"],
                                creation_time=key["createTime"],
                                restrictions=key.get("restrictions", {}),
                                project_id=project_id,
                            )
                        )

                    request = (
                        self.client.projects()
                        .locations()
                        .keys()
                        .list_next(previous_request=request, previous_response=response)
                    )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class Key(BaseModel):
    name: str
    id: str
    creation_time: str
    restrictions: dict
    project_id: str
