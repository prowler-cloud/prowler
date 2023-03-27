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
        self.tables = []
        self.__get_datasets__()
        self.__get_tables__()

    def __get_datasets__(self):
        try:
            request = self.client.datasets().list(projectId=self.project_id)
            while request is not None:
                response = request.execute()

                for dataset in response.get("datasets", []):
                    dataset_info = (
                        self.client.datasets()
                        .get(
                            projectId=self.project_id,
                            datasetId=dataset["datasetReference"]["datasetId"],
                        )
                        .execute()
                    )
                    cmk_encryption = False
                    public = False
                    roles = dataset_info.get("access", "")
                    if "allAuthenticatedUsers" in str(roles) or "allUsers" in str(
                        roles
                    ):
                        public = True
                    if dataset_info.get("defaultEncryptionConfiguration"):
                        cmk_encryption = True
                    self.datasets.append(
                        Dataset(
                            name=dataset["datasetReference"]["datasetId"],
                            id=dataset["id"],
                            region=dataset["location"],
                            cmk_encryption=cmk_encryption,
                            public=public,
                        )
                    )

                request = self.client.datasets().list_next(
                    previous_request=request, previous_response=response
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_tables__(self):
        try:
            for dataset in self.datasets:
                request = self.client.tables().list(
                    projectId=self.project_id, datasetId=dataset.name
                )
                while request is not None:
                    response = request.execute()

                    for table in response.get("tables", []):
                        cmk_encryption = False
                        if (
                            self.client.tables()
                            .get(
                                projectId=self.project_id,
                                datasetId=dataset.name,
                                tableId=table["tableReference"]["tableId"],
                            )
                            .execute()
                            .get("encryptionConfiguration")
                        ):
                            cmk_encryption = True
                        self.tables.append(
                            Table(
                                name=table["tableReference"]["tableId"],
                                id=table["id"],
                                region=dataset.region,
                                cmk_encryption=cmk_encryption,
                            )
                        )

                    request = self.client.tables().list_next(
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
    public: bool


class Table(BaseModel):
    name: str
    id: str
    region: str
    cmk_encryption: bool
