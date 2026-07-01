from prowler.providers.common.provider import Provider
from prowler.providers.googleworkspace.services.gmail.gmail_service import Gmail

gmail_client = Gmail(Provider.get_global_provider())
