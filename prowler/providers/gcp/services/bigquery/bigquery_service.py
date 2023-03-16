from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.gcp_provider import generate_client


################## BigQuery
class BigQuery:
    def __init__(self, audit_info):
        self.service = "bigquery"
        self.api_version = "v2"
        self.project_id = audit_info.project_id
        self.client = generate_client(self.service, self.api_version, audit_info)
        self.datasets = []
        self.__get_datasets__()

    def __get_datasets__(self):
        try:
            request = self.client.datasets().list(projectId=self.project_id)
            while request is not None:
                response = request.execute()

                for dataset in response.get("datasets", []):
                    cmk_encryption = False
                    if dataset.get("defaultEncryptionConfiguration"):
                        cmk_encryption = True
                    self.datasets.append(
                        Dataset(
                            name=dataset["datasetReference"]["datasetId"],
                            id=dataset["id"],
                            region=dataset["location"],
                            cmk_encryption=cmk_encryption,
                        )
                    )

                request = self.client.datasets().list_next(
                    previous_request=request, previous_response=response
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Dataset(BaseModel):
    name: str
    id: str
    region: str
    cmk_encryption: bool
