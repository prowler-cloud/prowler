from prowler.providers.aws.services.cloudtrail.cloudtrail_service import Cloudtrail
from prowler.providers.common.common import get_global_provider

cloudtrail_client = Cloudtrail(get_global_provider())
