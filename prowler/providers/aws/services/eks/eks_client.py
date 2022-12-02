from providers.aws.lib.audit_info.audit_info import current_audit_info
from providers.aws.services.eks.eks_service import EKS

eks_client = EKS(current_audit_info)
