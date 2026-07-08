from prowler.providers.common.provider import Provider
from prowler.providers.e2enetworks.services.node.node_service import Nodes

node_client = Nodes(Provider.get_global_provider())
