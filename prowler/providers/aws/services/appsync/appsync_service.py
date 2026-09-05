from typing import Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class AppSync(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.graphql_apis = {}
        self.__threading_call__(self._list_graphql_apis)
        self.__threading_call__(self._list_resolvers)
        self.__threading_call__(self._list_data_sources)

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

    def _list_resolvers(self, regional_client):
        logger.info("AppSync - Listing Resolvers...")
        try:
            for api_arn, api in self.graphql_apis.items():
                if api.region == regional_client.region:
                    # List types first
                    list_types_paginator = regional_client.get_paginator("list_types")
                    for type_page in list_types_paginator.paginate(
                        apiId=api.id, format="SDL"
                    ):
                        for type_item in type_page.get("types", []):
                            type_name = type_item.get("name")
                            # List resolvers for each type
                            list_resolvers_paginator = regional_client.get_paginator(
                                "list_resolvers"
                            )
                            for resolver_page in list_resolvers_paginator.paginate(
                                apiId=api.id, typeName=type_name
                            ):
                                for resolver in resolver_page.get("resolvers", []):
                                    # Get full resolver details including mapping templates
                                    try:
                                        resolver_details = regional_client.get_resolver(
                                            apiId=api.id,
                                            typeName=type_name,
                                            fieldName=resolver.get("fieldName"),
                                        )
                                        resolver_data = resolver_details.get(
                                            "resolver", {}
                                        )
                                        resolver_arn = resolver_data.get(
                                            "resolverArn", ""
                                        )

                                        api.resolvers.append(
                                            Resolver(
                                                arn=resolver_arn,
                                                type_name=type_name,
                                                field_name=resolver_data.get(
                                                    "fieldName", ""
                                                ),
                                                request_mapping_template=resolver_data.get(
                                                    "requestMappingTemplate", ""
                                                ),
                                                response_mapping_template=resolver_data.get(
                                                    "responseMappingTemplate", ""
                                                ),
                                                data_source_name=resolver_data.get(
                                                    "dataSourceName", ""
                                                ),
                                            )
                                        )
                                    except Exception as resolver_error:
                                        logger.error(
                                            f"{regional_client.region} -- {resolver_error.__class__.__name__}[{resolver_error.__traceback__.tb_lineno}]: {resolver_error}"
                                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_data_sources(self, regional_client):
        logger.info("AppSync - Listing Data Sources...")
        try:
            for api_arn, api in self.graphql_apis.items():
                if api.region == regional_client.region:
                    list_data_sources_paginator = regional_client.get_paginator(
                        "list_data_sources"
                    )
                    for page in list_data_sources_paginator.paginate(apiId=api.id):
                        for data_source in page.get("dataSources", []):
                            data_source_arn = data_source.get("dataSourceArn", "")
                            api.data_sources.append(
                                DataSource(
                                    arn=data_source_arn,
                                    name=data_source.get("name", ""),
                                    type=data_source.get("type", ""),
                                    dynamodb_config=data_source.get(
                                        "dynamodbConfig", {}
                                    ),
                                    lambda_config=data_source.get("lambdaConfig", {}),
                                    elasticsearch_config=data_source.get(
                                        "elasticsearchConfig", {}
                                    ),
                                    opensearchservice_config=data_source.get(
                                        "openSearchServiceConfig", {}
                                    ),
                                    http_config=data_source.get("httpConfig", {}),
                                    relational_database_config=data_source.get(
                                        "relationalDatabaseConfig", {}
                                    ),
                                    event_bridge_config=data_source.get(
                                        "eventBridgeConfig", {}
                                    ),
                                )
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
    resolvers: list = []
    data_sources: list = []


class Resolver(BaseModel):
    arn: str
    type_name: str
    field_name: str
    request_mapping_template: str = ""
    response_mapping_template: str = ""
    data_source_name: str = ""


class DataSource(BaseModel):
    arn: str
    name: str
    type: str
    dynamodb_config: dict = {}
    lambda_config: dict = {}
    elasticsearch_config: dict = {}
    opensearchservice_config: dict = {}
    http_config: dict = {}
    relational_database_config: dict = {}
    event_bridge_config: dict = {}
