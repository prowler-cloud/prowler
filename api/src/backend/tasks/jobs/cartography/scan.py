import neo4j

from cartography.config import Config as CartographyConfig
from cartography.intel import create_indexes as cartography_indexes

from api.models import Provider
from api.utils import initialize_prowler_provider
from prowler.providers.common.provider import Provider
from tasks.jobs.cartography.aws import start_aws_ingestion

CARTOGRAPHY_INGESTION_FUNCTIONS = {
    "aws": start_aws_ingestion,
}


def run(provider_id: str) -> None:
    provider = Provider.objects.get(id=provider_id)
    prowler_provider = initialize_prowler_provider(provider)

    # TODO: Proper Neo4j configuration
    neo4j_uri = "bolt://neo4j:7687"
    neo4j_user = "neo4j"
    neo4j_password = "neo4j_password"

    config = CartographyConfig()

    with neo4j.GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password)) as driver:
        with driver.session() as neo4j_session:
            cartography_indexes.run(neo4j_session, config)
            CARTOGRAPHY_INGESTION_FUNCTIONS[provider.provider](neo4j_session, config, prowler_provider)
