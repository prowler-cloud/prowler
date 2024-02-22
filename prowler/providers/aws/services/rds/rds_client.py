from prowler.providers.aws.services.rds.rds_service import RDS
from prowler.providers.common.common import get_global_provider

rds_client = RDS(get_global_provider())
