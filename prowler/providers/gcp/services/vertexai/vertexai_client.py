from prowler.providers.common.provider import Provider
from prowler.providers.gcp.services.vertexai.vertexai_service import VertexAI

vertexai_client = VertexAI(Provider.get_global_provider())
