from prowler.providers.aws.services.eks.eks_service import EKS
from prowler.providers.common.common import get_global_provider

eks_client = EKS(get_global_provider())
