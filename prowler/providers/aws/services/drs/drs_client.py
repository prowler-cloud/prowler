from prowler.providers.aws.services.drs.drs_service import DRS
from prowler.providers.common.common import get_global_provider

drs_client = DRS(get_global_provider())
