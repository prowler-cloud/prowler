from prowler.providers.common.provider import Provider
from prowler.providers.gcp.services.iam.iam_service import AccessApproval

accessapproval_client = AccessApproval(Provider.get_global_provider())
