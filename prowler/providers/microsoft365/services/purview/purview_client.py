from prowler.providers.common.provider import Provider
from prowler.providers.microsoft365.services.purview.purview_service import Purview

purview_client = Purview(Provider.get_global_provider())
