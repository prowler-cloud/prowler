from prowler.providers.aws.services.glacier.glacier_service import Glacier
from prowler.providers.common.common import get_global_provider

glacier_client = Glacier(get_global_provider())
