from prowler.providers.common.provider import Provider
from prowler.providers.microsoft365.services.admincenter.admincenter_service import (
    AdminCenter,
)

admincenter_client = AdminCenter(Provider.get_global_provider())
