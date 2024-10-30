from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class AppSync(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.graphqlapis = {}
        self.__threading_call__(self._list_graphql_apis)

    def _list_graphql_apis(self, regional_client):
        logger.info("AppSync - Describing APIs...")
        try:
            list_graphql_apis_paginator = regional_client.get_paginator(
                "list_graphql_apis"
            )
            for page in list_graphql_apis_paginator.paginate():
                for api in page["graphqlApis"]:
                    api_arn = api["arn"]
                    if not self.audit_resources or (
                        is_resource_filtered(
                            api_arn,
                            self.audit_resources,
                        )
                    ):
                        aux_tags = []
                        if api.get("tags"):
                            aux_tags.append(api.get("tags"))
                        self.graphqlapis[api_arn] = GraphqlApi(
                            id=api["apiId"],
                            name=api["name"],
                            arn=api_arn,
                            region=regional_client.region,
                            type=api.get("apiType"),
                            field_log_level=api.get("logConfig", {}).get(
                                "fieldLogLevel", ""
                            ),
                            authentication_type=api.get("authenticationType", ""),
                            tags=aux_tags,
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class GraphqlApi(BaseModel):
    id: str
    name: str
    arn: str
    region: str
    type: Optional[str]
    field_log_level: Optional[str]
    authentication_type: Optional[str]
    tags: Optional[list] = []
