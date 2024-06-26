from prowler.providers.aws.services.fms.fms_service import FMS
from prowler.providers.common.provider import Provider

fms_client = FMS(Provider.get_global_provider())
