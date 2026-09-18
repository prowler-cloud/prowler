from prowler.providers.aws.services.oam.oam_service import OAM
from prowler.providers.common.provider import Provider

oam_client = OAM(Provider.get_global_provider())
