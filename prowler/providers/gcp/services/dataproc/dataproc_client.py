from prowler.providers.common.common import get_global_provider
from prowler.providers.gcp.services.dataproc.dataproc_service import Dataproc

dataproc_client = Dataproc(get_global_provider())
