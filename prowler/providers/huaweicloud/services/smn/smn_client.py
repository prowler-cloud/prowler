from prowler.providers.huaweicloud.services.smn.smn_service import SMN
from prowler.providers.common.provider import Provider

smn_client = SMN(Provider.get_global_provider())
