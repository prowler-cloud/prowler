from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################################ ResourceExplorer2
class ResourceExplorer2(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__("resource-explorer-2", provider)
        self.index_arn_template = f"arn:{self.audited_partition}:resource-explorer:{self.region}:{self.audited_account}:index"
        self.indexes = []
        self.__threading_call__(self._list_indexes)

    def _list_indexes(self, regional_client):
        logger.info("ResourceExplorer - list indexes...")
        try:
            list_indexes_paginator = regional_client.get_paginator("list_indexes")
            for page in list_indexes_paginator.paginate():
                for index in page.get("Indexes"):
                    if not self.audit_resources or (
                        is_resource_filtered(index["Arn"], self.audit_resources)
                    ):
                        if self.indexes is None:
                            self.indexes = []
                        self.indexes.append(
                            Indexes(
                                arn=index["Arn"],
                                region=index["Region"],
                                type=index["Type"],
                            )
                        )
        except ClientError as error:
            if error.response["Error"]["Code"] == "AccessDeniedException":
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                if not self.indexes:
                    self.indexes = None
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Indexes(BaseModel):
    arn: str
    region: str
    type: str
