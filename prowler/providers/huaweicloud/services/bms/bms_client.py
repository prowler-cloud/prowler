from prowler.providers.huaweicloud.services.bms.bms_service import BMS
from prowler.providers.common.provider import Provider

bms_client = BMS(Provider.get_global_provider())
