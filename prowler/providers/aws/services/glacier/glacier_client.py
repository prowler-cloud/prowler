from prowler.providers.aws.services.glacier.glacier_service import Glacier
from prowler.providers.common.provider import Provider

glacier_client = Glacier(Provider.get_global_provider())
