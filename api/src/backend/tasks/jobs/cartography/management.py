import contextlib

import neo4j

from cartography.config import Config as CartographyConfig


# TODO: A driver creation is expensive, but as this is going to be executed in a Celery task, it's ok for now
#       For the API we should create the driver at startup, use it for creating sessions, and close it at shutdown
@contextlib.contextmanager
def create_neo4j_session(config: CartographyConfig, database: str | None = None) -> neo4j.Session:
    with neo4j.GraphDatabase.driver(
        config.neo4j_uri, auth=(config.neo4j_user, config.neo4j_password), database=database
    ) as driver:
        driver.verify_connectivity()
        with driver.session() as neo4j_session:
            yield neo4j_session


def create_neo4j_database(
    config: CartographyConfig,
    database: str,
) -> None:
    with create_neo4j_session(config) as neo4j_session:
        neo4j_session.run(
            query="CREATE DATABASE $database IF NOT EXISTS",
            parameters={"database": database},
        )


# TODO: Remember to use this function when a tenant is deleted
def drop_neo4j_database(
    config: CartographyConfig,
    database: str,
) -> None:
    with create_neo4j_session(config) as neo4j_session:
        neo4j_session.run(
            query="DROP DATABASE $database IF EXISTS DESTROY DATA",
            parameters={"database": database},
        )


# TODO: Remember to use this function when a tenant delete a cloud provider
def drop_neo4j_account_subgraph(
    config: CartographyConfig,
    database: str,
    root_node_label: str,
    account_id: str,
) -> None:
    query = """
        MATCH (a:__ROOT_NODE_LABEL__ {id: $account_id}})
        CALL apoc.path.subgraphNodes(a, {})
        YIELD node
        DETACH DELETE node
    """.replace("__ROOT_NODE_LABEL__", root_node_label)

    with create_neo4j_session(config, database) as neo4j_session:
        neo4j_session.run(
            query=query,
            parameters={"account_id": account_id},
        )
