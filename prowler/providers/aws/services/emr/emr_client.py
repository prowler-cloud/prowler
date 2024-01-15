from prowler.providers.aws.services.emr.emr_service import EMR
from prowler.providers.common.common import get_global_provider

emr_client = EMR(get_global_provider())
