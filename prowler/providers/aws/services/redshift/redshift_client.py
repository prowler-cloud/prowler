from prowler.providers.aws.services.redshift.redshift_service import Redshift
from prowler.providers.common.common import get_global_provider

redshift_client = Redshift(get_global_provider())
