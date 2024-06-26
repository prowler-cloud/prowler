from prowler.providers.aws.services.dlm.dlm_service import DLM
from prowler.providers.common.provider import Provider

dlm_client = DLM(Provider.get_global_provider())
