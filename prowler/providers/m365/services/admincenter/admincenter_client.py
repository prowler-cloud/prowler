from prowler.providers.common.provider import Provider
from prowler.providers.m365.services.admincenter.admincenter_service import AdminCenter

admincenter_client = AdminCenter(Provider.get_global_provider())
