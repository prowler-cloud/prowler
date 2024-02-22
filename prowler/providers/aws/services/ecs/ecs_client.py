from prowler.providers.aws.services.ecs.ecs_service import ECS
from prowler.providers.common.common import get_global_provider

ecs_client = ECS(get_global_provider())
