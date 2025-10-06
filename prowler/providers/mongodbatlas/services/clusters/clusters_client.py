from prowler.providers.common.provider import Provider
from prowler.providers.mongodbatlas.services.clusters.clusters_service import Clusters

clusters_client = Clusters(Provider.get_global_provider())
