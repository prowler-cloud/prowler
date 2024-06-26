from prowler.providers.aws.services.redshift.redshift_service import Redshift
from prowler.providers.common.provider import Provider

redshift_client = Redshift(Provider.get_global_provider())
