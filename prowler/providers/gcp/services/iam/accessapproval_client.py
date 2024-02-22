from prowler.providers.common.common import get_global_provider
from prowler.providers.gcp.services.iam.iam_service import AccessApproval

accessapproval_client = AccessApproval(get_global_provider())
