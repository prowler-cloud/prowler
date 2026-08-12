
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


class VPN(HuaweiCloudService):
    """
    VPN service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud VPN service
    to retrieve VPN connections and their encryption policies.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)

        self.vpn_connections: List[VpnConnection] = []

        if self.session.is_mock:
            self._load_mock_data()
            return

        self._list_vpn_connections()

    def _load_mock_data(self):
        """Load mock data for testing."""
        region = "la-south-2"
        self.vpn_connections = [
            VpnConnection(
                id="vpn-mock-001",
                name="vpn-connection-1",
                status="ACTIVE",
                ike_encryption_algorithm="aes-256",
                ipsec_encryption_algorithm="aes-256",
                region=region,
            ),
            VpnConnection(
                id="vpn-mock-002",
                name="vpn-connection-2",
                status="ACTIVE",
                ike_encryption_algorithm="3des",
                ipsec_encryption_algorithm="aes-128",
                region=region,
            ),
        ]

    def _list_vpn_connections(self):
        """List all VPN connections across regions."""
        if not self.regional_clients:
            return

        for region, client in self.regional_clients.items():
            logger.info(f"VPN - Listing VPN Connections in {region}...")

            try:
                from huaweicloudsdkvpn.v5 import ListVpnConnectionsRequest

                request = ListVpnConnectionsRequest()
                response = self._call_with_retries(client.list_vpn_connections, request)

                if response and response.vpn_connections:
                    for conn in response.vpn_connections:
                        ike_enc = ""
                        ipsec_enc = ""

                        ike_policy = getattr(conn, "ikepolicy", None)
                        if ike_policy:
                            ike_enc = (
                                getattr(ike_policy, "encryption_algorithm", "") or ""
                            )

                        ipsec_policy = getattr(conn, "ipsecpolicy", None)
                        if ipsec_policy:
                            ipsec_enc = (
                                getattr(ipsec_policy, "encryption_algorithm", "") or ""
                            )

                        self.vpn_connections.append(
                            VpnConnection(
                                id=getattr(conn, "id", ""),
                                name=getattr(conn, "name", ""),
                                status=getattr(conn, "status", ""),
                                ike_encryption_algorithm=ike_enc,
                                ipsec_encryption_algorithm=ipsec_enc,
                                region=region,
                            )
                        )

            except Exception as error:
                logger.error(
                    f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class VpnConnection(BaseModel):
    """VPN Connection model."""

    id: str
    name: str = ""
    status: str = ""
    ike_encryption_algorithm: str = ""
    ipsec_encryption_algorithm: str = ""
    region: str = ""
