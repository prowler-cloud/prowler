from prowler.providers.huaweicloud.services.tms.tms_service import TMS
from prowler.providers.common.provider import Provider

tms_client = TMS(Provider.get_global_provider())
