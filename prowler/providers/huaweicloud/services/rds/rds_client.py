from prowler.providers.common.provider import Provider
from prowler.providers.huaweicloud.services.rds.rds_service import RDS

rds_client = RDS(Provider.get_global_provider())
