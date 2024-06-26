from prowler.providers.common.provider import Provider
from prowler.providers.gcp.services.iam.iam_service import EssentialContacts

essentialcontacts_client = EssentialContacts(Provider.get_global_provider())
