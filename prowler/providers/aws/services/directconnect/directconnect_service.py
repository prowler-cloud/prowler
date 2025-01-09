from typing import Optional

from botocore.exceptions import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class DirectConnect(AWSService):
    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.connections = {}
        self.vifs = {}
        self.vgws = {}
        self.dxgws = {}
        self.__threading_call__(self._describe_connections)
        self.__threading_call__(self._describe_vifs)

    def _get_connection_arn_template(self, region):
        return (
            f"arn:{self.audited_partition}:directconnect:{region}:{self.audited_account}:dxcon"
            if region
            else f"arn:{self.audited_partition}:directconnect:{self.region}:{self.audited_account}:dxcon"
        )

    def _describe_connections(self, regional_client):
        """List DirectConnect(s) in the given region.

        Args:
            regional_client: The regional AWS client.
        """

        try:
            logger.info("DirectConnect - Listing Connections...")
            dx_connect = regional_client.describe_connections()

            for connection in dx_connect["connections"]:
                connection_arn = f"arn:{self.audited_partition}:directconnect:{regional_client.region}:{self.audited_account}:dxcon/{connection['connectionId']}"
                if not self.audit_resources or (
                    is_resource_filtered(connection_arn, self.audit_resources)
                ):
                    self.connections[connection_arn] = Connection(
                        arn=connection_arn,
                        id=connection["connectionId"],
                        name=connection["connectionName"],
                        location=connection["location"],
                        region=regional_client.region,
                    )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_vifs(self, regional_client):
        """Describe each DirectConnect VIFs."""

        logger.info("DirectConnect - Describing VIFs...")
        try:
            describe_vifs = regional_client.describe_virtual_interfaces()
            for vif in describe_vifs["virtualInterfaces"]:
                vif_id = vif["virtualInterfaceId"]
                vif_arn = f"arn:{self.audited_partition}:directconnect:{regional_client.region}:{self.audited_account}:dxvif/{vif_id}"
                if not self.audit_resources or (
                    is_resource_filtered(vif_arn, self.audit_resources)
                ):
                    vgw_id = vif.get("virtualGatewayId")
                    connection_id = vif.get("connectionId")
                    dxgw_id = vif.get("directConnectGatewayId")
                    self.vifs[vif_arn] = VirtualInterface(
                        arn=vif_arn,
                        id=vif_id,
                        name=vif["virtualInterfaceName"],
                        connection_id=connection_id,
                        vgw_gateway_id=vif["virtualGatewayId"],
                        dx_gateway_id=dxgw_id,
                        location=vif["location"],
                        region=regional_client.region,
                    )
                    if vgw_id:
                        vgw_arn = f"arn:{self.audited_partition}:directconnect:{regional_client.region}:{self.audited_account}:virtual-gateway/{vgw_id}"
                        if vgw_arn in self.vgws:
                            self.vgws[vgw_arn].vifs.append(vif_id)
                            self.vgws[vgw_arn].connections.append(connection_id)
                        else:
                            self.vgws[vgw_arn] = VirtualGateway(
                                arn=vgw_arn,
                                id=vgw_id,
                                vifs=[vif_id],
                                connections=[connection_id],
                                region=regional_client.region,
                            )

                    if dxgw_id:
                        dxgw_arn = f"arn:{self.audited_partition}:directconnect:{regional_client.region}:{self.audited_account}:dx-gateway/{dxgw_id}"
                        if dxgw_arn in self.dxgws:
                            self.dxgws[dxgw_arn].vifs.append(vif_id)
                            self.dxgws[dxgw_arn].connections.append(connection_id)
                        else:
                            self.dxgws[dxgw_arn] = DXGateway(
                                arn=dxgw_arn,
                                id=dxgw_id,
                                vifs=[vif_id],
                                connections=[connection_id],
                                region=regional_client.region,
                            )
        except ClientError as error:
            if error.response["Error"]["Code"] == "ResourceNotFoundException":
                logger.warning(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Connection(BaseModel):
    arn = str
    id: str
    name: Optional[str] = None
    location: str
    region: str


class VirtualInterface(BaseModel):
    arn: str
    id: str
    name: str
    connection_id: Optional[str] = None
    vgw_gateway_id: str
    dx_gateway_id: str
    location: str
    region: str


class VirtualGateway(BaseModel):
    arn: str
    id: str
    vifs: list
    connections: list
    region: str


class DXGateway(BaseModel):
    arn: str
    id: str
    vifs: list
    connections: list
    region: str
