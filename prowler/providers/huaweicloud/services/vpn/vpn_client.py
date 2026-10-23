from prowler.providers.huaweicloud.services.vpn.vpn_service import VPN
from prowler.providers.common.provider import Provider

vpn_client = VPN(Provider.get_global_provider())
