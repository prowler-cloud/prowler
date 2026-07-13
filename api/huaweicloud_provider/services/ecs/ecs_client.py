from prowler.providers.huaweicloud.services.ecs.ecs_service import ECS
from prowler.providers.common.provider import Provider

ecs_client = ECS(Provider.get_global_provider())
