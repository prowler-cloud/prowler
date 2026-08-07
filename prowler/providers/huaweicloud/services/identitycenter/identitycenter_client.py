from prowler.providers.huaweicloud.services.identitycenter.identitycenter_service import IdentityCenter
from prowler.providers.common.provider import Provider

identitycenter_client = IdentityCenter(Provider.get_global_provider())
