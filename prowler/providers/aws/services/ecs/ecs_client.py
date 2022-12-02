from providers.aws.lib.audit_info.audit_info import current_audit_info
from providers.aws.services.ecs.ecs_service import ECS

ecs_client = ECS(current_audit_info)
