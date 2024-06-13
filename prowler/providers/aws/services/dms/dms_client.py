from prowler.providers.aws.services.dms.dms_service import DMS
from prowler.providers.common.provider import Provider

dms_client = DMS(Provider.get_global_provider())
