from prowler.providers.aws.services.drs.drs_service import DRS
from prowler.providers.common.provider import Provider

drs_client = DRS(Provider.get_global_provider())
