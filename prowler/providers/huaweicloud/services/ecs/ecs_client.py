from prowler.providers.common.provider import Provider
from prowler.providers.huaweicloud.services.ecs.ecs_service import ECS

ecs_client = ECS(Provider.get_global_provider())
