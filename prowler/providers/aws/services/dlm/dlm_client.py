from prowler.providers.aws.services.dlm.dlm_service import DLM
from prowler.providers.common.common import get_global_provider

dlm_client = DLM(get_global_provider())
