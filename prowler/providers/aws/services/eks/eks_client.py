from prowler.providers.aws.services.eks.eks_service import EKS
from prowler.providers.common.provider import Provider

eks_client = EKS(Provider.get_global_provider())
