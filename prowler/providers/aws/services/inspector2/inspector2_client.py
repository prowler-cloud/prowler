from prowler.providers.aws.services.inspector2.inspector2_service import Inspector2
from prowler.providers.common.common import get_global_provider

inspector2_client = Inspector2(get_global_provider())
