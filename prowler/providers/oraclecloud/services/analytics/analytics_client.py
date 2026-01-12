"""OCI Analytics client."""

from prowler.providers.common.provider import Provider
from prowler.providers.oraclecloud.services.analytics.analytics_service import Analytics

analytics_client = Analytics(Provider.get_global_provider())
