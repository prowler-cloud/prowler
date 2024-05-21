from prowler.providers.common.provider import Provider
from prowler.providers.gcp.services.dataproc.dataproc_service import Dataproc

dataproc_client = Dataproc(Provider.get_global_provider())
