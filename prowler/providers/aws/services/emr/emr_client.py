from prowler.providers.aws.services.emr.emr_service import EMR
from prowler.providers.common.provider import Provider

emr_client = EMR(Provider.get_global_provider())
