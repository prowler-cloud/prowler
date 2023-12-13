from prowler.providers.common.common import global_provider
from prowler.providers.gcp.services.iam.iam_service import AccessApproval

accessapproval_client = AccessApproval(global_provider)
