from prowler.providers.aws.services.fsx.fsx_service import FSx
from prowler.providers.common.provider import Provider

fsx_client = FSx(Provider.get_global_provider())
