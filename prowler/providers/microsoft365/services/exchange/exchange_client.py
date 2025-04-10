from prowler.providers.common.provider import Provider
from prowler.providers.microsoft365.services.exchange.exchange_service import Exchange

exchange_client = Exchange(Provider.get_global_provider())
