from prowler.providers.common.provider import Provider
from prowler.providers.m365.services.sharepoint.sharepoint_service import SharePoint

sharepoint_client = SharePoint(Provider.get_global_provider())
