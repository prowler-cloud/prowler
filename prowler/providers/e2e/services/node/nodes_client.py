from prowler.providers.common.provider import Provider
from prowler.providers.e2e.services.node.nodes_service import Nodes

nodes_client = Nodes(Provider.get_global_provider())
