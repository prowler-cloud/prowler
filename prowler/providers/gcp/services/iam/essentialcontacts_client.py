from prowler.providers.common.common import get_global_provider
from prowler.providers.gcp.services.iam.iam_service import EssentialContacts

essentialcontacts_client = EssentialContacts(get_global_provider())
