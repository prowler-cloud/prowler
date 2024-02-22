from prowler.providers.aws.services.fms.fms_service import FMS
from prowler.providers.common.common import get_global_provider

fms_client = FMS(get_global_provider())
