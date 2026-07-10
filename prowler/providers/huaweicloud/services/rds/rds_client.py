from prowler.providers.huaweicloud.services.rds.rds_service import RDS
from prowler.providers.common.provider import Provider

rds_client = RDS(Provider.get_global_provider())
