from prowler.providers.common.provider import Provider
from prowler.providers.okta.services.systemlog.systemlog_service import SystemLog

systemlog_client = SystemLog(Provider.get_global_provider())
