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
        self.__threading_call__(self._get_resolvers)
        self.__threading_call__(self._get_data_sources)

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

    def _get_resolvers(self, regional_client):
        logger.info("AppSync - Describing Resolvers...")
        try:
            for api in self.graphql_apis.values():
                if api.region != regional_client.region:
                    continue
                try:
                    list_resolvers_paginator = regional_client.get_paginator(
                        "list_resolvers"
                    )
                    for page in list_resolvers_paginator.paginate(
                        graphqlApiId=api.id
                    ):
                        for resolver in page.get("resolvers", []):
                            resolver_arn = resolver.get("resolverArn", "")
                            # Get the full resolver details (mapping templates)
                            try:
                                resolver_detail = regional_client.get_resolver(
                                    graphqlApiId=api.id,
                                    typeName=resolver["typeName"],
                                    fieldName=resolver["fieldName"],
                                )
                                resolver_data = resolver_detail.get("resolver", {})
                                api.resolvers.append(
                                    Resolver(
                                        arn=resolver_arn,
                                        type_name=resolver.get("typeName", ""),
                                        field_name=resolver.get("fieldName", ""),
                                        data_source_name=resolver.get(
                                            "dataSourceName", ""
                                        ),
                                        kind=resolver.get("kind", "UNIT"),
                                        request_mapping_template=resolver_data.get(
                                            "requestMappingTemplate", ""
                                        ),
                                        response_mapping_template=resolver_data.get(
                                            "responseMappingTemplate", ""
                                        ),
                                        pipeline_functions=resolver_data.get(
                                            "pipelineConfig", {}
                                        )
                                        .get("functions", []),
                                        region=regional_client.region,
                                    )
                                )
                            except Exception as error:
                                logger.error(
                                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                                )
                except Exception as error:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_data_sources(self, regional_client):
        logger.info("AppSync - Describing Data Sources...")
        try:
            for api in self.graphql_apis.values():
                if api.region != regional_client.region:
                    continue
                try:
                    list_data_sources_paginator = regional_client.get_paginator(
                        "list_data_sources"
                    )
                    for page in list_data_sources_paginator.paginate(
                        graphqlApiId=api.id
                    ):
                        for data_source in page.get("dataSources", []):
                            data_source_arn = data_source.get("dataSourceArn", "")
                            # Get full data source details
                            try:
                                data_source_detail = regional_client.get_data_source(
                                    graphqlApiId=api.id,
                                    name=data_source["name"],
                                )
                                ds_data = data_source_detail.get("dataSource", {})
                                api.data_sources.append(
                                    DataSource(
                                        arn=data_source_arn,
                                        name=ds_data.get("name", ""),
                                        type=ds_data.get("type", ""),
                                        description=ds_data.get("description", ""),
                                        lambda_config=ds_data.get("lambdaConfig", {}),
                                        dynamodb_config=ds_data.get(
                                            "dynamodbConfig", {}
                                        ),
                                        elasticsearch_config=ds_data.get(
                                            "elasticsearchConfig", {}
                                        ),
                                        http_config=ds_data.get("httpConfig", {}),
                                        relational_database_config=ds_data.get(
                                            "relationalDatabaseConfig", {}
                                        ),
                                        region=regional_client.region,
                                    )
                                )
                            except Exception as error:
                                logger.error(
                                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                                )
                except Exception as error:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Resolver(BaseModel):
    arn: str
    type_name: str
    field_name: str
    data_source_name: str
    kind: str
    request_mapping_template: str
    response_mapping_template: str
    pipeline_functions: list
    region: str


class DataSource(BaseModel):
    arn: str
    name: str
    type: str
    description: str
    lambda_config: dict
    dynamodb_config: dict
    elasticsearch_config: dict
    http_config: dict
    relational_database_config: dict
    region: str


class GraphqlApi(BaseModel):
    id: str
    name: str
    arn: str
    region: str
    type: str
    field_log_level: str
    authentication_type: str
    resolvers: list[Resolver] = []
    data_sources: list[DataSource] = []
    tags: Optional[list] = []
