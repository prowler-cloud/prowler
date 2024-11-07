from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class AppSync(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.graphql_apis = {}
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
                        self.graphql_apis[api_arn] = GraphqlApi(
                            id=api["apiId"],
                            name=api["name"],
                            arn=api_arn,
                            region=regional_client.region,
                            type=api.get("apiType", "GRAPHQL"),
                            field_log_level=api.get("logConfig", {}).get(
                                "fieldLogLevel", ""
                            ),
                            authentication_type=api.get(
                                "authenticationType", "API_KEY"
                            ),
                            tags=[api.get("tags", {})],
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
    type: str
    field_log_level: str
    authentication_type: str
    tags: Optional[list] = []
