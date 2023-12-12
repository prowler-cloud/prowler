from prowler.providers.common.common import global_provider
from prowler.providers.gcp.services.dataproc.dataproc_service import Dataproc

dataproc_client = Dataproc(global_provider)
