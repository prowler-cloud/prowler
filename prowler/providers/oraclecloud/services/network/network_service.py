"""OCI Network Service Module."""

from datetime import datetime
from typing import Optional

import oci
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.oraclecloud.lib.service.service import OCIService


class Network(OCIService):
    """OCI Network Service class to retrieve VCNs, security lists, and network security groups."""

    def __init__(self, provider):
        """
        Initialize the Network service.

        Args:
            provider: The OCI provider instance
        """
        super().__init__("network", provider)
        self.vcns = []
        self.security_lists = []
        self.network_security_groups = []
        self.subnets = []
        self.__threading_call_by_region_and_compartment__(self.__list_vcns__)
        self.__threading_call_by_region_and_compartment__(self.__list_security_lists__)
        self.__threading_call_by_region_and_compartment__(
            self.__list_network_security_groups__
        )
        self.__threading_call_by_region_and_compartment__(self.__list_subnets__)

    def __get_client__(self, region):
        """
        Get the VirtualNetwork client for a region.

        Args:
            region: Region key

        Returns:
            VirtualNetwork client instance
        """
        return self._create_oci_client(
            oci.core.VirtualNetworkClient, config_overrides={"region": region}
        )

    def __list_vcns__(self, region, compartment):
        """
        List all VCNs in a compartment and region.

        Args:
            region: OCIRegion object
            compartment: Compartment object
        """
        try:
            region_key = region.key if hasattr(region, "key") else str(region)
            vcn_client = self.__get_client__(region_key)

            logger.info(
                f"Network - Listing VCNs in {region_key} - {compartment.name}..."
            )

            vcns_data = oci.pagination.list_call_get_all_results(
                vcn_client.list_vcns, compartment_id=compartment.id
            ).data

            for vcn in vcns_data:
                if vcn.lifecycle_state != "TERMINATED":
                    # Get default security list
                    default_security_list_id = vcn.default_security_list_id

                    self.vcns.append(
                        VCN(
                            id=vcn.id,
                            display_name=(
                                vcn.display_name if hasattr(vcn, "display_name") else ""
                            ),
                            compartment_id=compartment.id,
                            cidr_blocks=(
                                vcn.cidr_blocks if hasattr(vcn, "cidr_blocks") else []
                            ),
                            lifecycle_state=vcn.lifecycle_state,
                            default_security_list_id=default_security_list_id,
                            region=region_key,
                            time_created=vcn.time_created,
                        )
                    )
        except Exception as error:
            logger.error(
                f"{region_key} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_security_lists__(self, region, compartment):
        """
        List all security lists in a compartment and region.

        Args:
            region: OCIRegion object
            compartment: Compartment object
        """
        try:
            region_key = region.key if hasattr(region, "key") else str(region)
            vcn_client = self.__get_client__(region_key)

            logger.info(
                f"Network - Listing Security Lists in {region_key} - {compartment.name}..."
            )

            security_lists_data = oci.pagination.list_call_get_all_results(
                vcn_client.list_security_lists, compartment_id=compartment.id
            ).data

            for sec_list in security_lists_data:
                if sec_list.lifecycle_state != "TERMINATED":
                    # Check if this is a default security list
                    is_default = False
                    vcn_id = sec_list.vcn_id
                    for vcn in self.vcns:
                        if (
                            vcn.id == vcn_id
                            and vcn.default_security_list_id == sec_list.id
                        ):
                            is_default = True
                            break

                    # Convert OCI SDK objects to dict for JSON serialization
                    ingress_rules = [
                        oci.util.to_dict(rule)
                        for rule in (sec_list.ingress_security_rules or [])
                    ]
                    egress_rules = [
                        oci.util.to_dict(rule)
                        for rule in (sec_list.egress_security_rules or [])
                    ]

                    self.security_lists.append(
                        SecurityList(
                            id=sec_list.id,
                            display_name=(
                                sec_list.display_name
                                if hasattr(sec_list, "display_name")
                                else ""
                            ),
                            compartment_id=compartment.id,
                            vcn_id=sec_list.vcn_id,
                            ingress_security_rules=ingress_rules,
                            egress_security_rules=egress_rules,
                            lifecycle_state=sec_list.lifecycle_state,
                            is_default=is_default,
                            region=region_key,
                            time_created=sec_list.time_created,
                        )
                    )
        except Exception as error:
            logger.error(
                f"{region_key} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_network_security_groups__(self, region, compartment):
        """
        List all network security groups in a compartment and region.

        Args:
            region: OCIRegion object
            compartment: Compartment object
        """
        try:
            region_key = region.key if hasattr(region, "key") else str(region)
            vcn_client = self.__get_client__(region_key)

            logger.info(
                f"Network - Listing Network Security Groups in {region_key} - {compartment.name}..."
            )

            nsgs_data = oci.pagination.list_call_get_all_results(
                vcn_client.list_network_security_groups, compartment_id=compartment.id
            ).data

            for nsg in nsgs_data:
                if nsg.lifecycle_state != "TERMINATED":
                    # Get NSG rules
                    try:
                        nsg_rules_data = oci.pagination.list_call_get_all_results(
                            vcn_client.list_network_security_group_security_rules,
                            network_security_group_id=nsg.id,
                        ).data
                        # Convert OCI SDK objects to dict for JSON serialization
                        nsg_rules = [oci.util.to_dict(rule) for rule in nsg_rules_data]
                    except Exception:
                        nsg_rules = []

                    self.network_security_groups.append(
                        NetworkSecurityGroup(
                            id=nsg.id,
                            display_name=(
                                nsg.display_name if hasattr(nsg, "display_name") else ""
                            ),
                            compartment_id=compartment.id,
                            vcn_id=nsg.vcn_id,
                            security_rules=nsg_rules,
                            lifecycle_state=nsg.lifecycle_state,
                            region=region_key,
                            time_created=nsg.time_created,
                        )
                    )
        except Exception as error:
            logger.error(
                f"{region_key} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_subnets__(self, region, compartment):
        """
        List all subnets in a compartment and region.

        Args:
            region: OCIRegion object
            compartment: Compartment object
        """
        try:
            region_key = region.key if hasattr(region, "key") else str(region)
            vcn_client = self.__get_client__(region_key)

            logger.info(
                f"Network - Listing Subnets in {region_key} - {compartment.name}..."
            )

            subnets_data = oci.pagination.list_call_get_all_results(
                vcn_client.list_subnets, compartment_id=compartment.id
            ).data

            for subnet in subnets_data:
                if subnet.lifecycle_state != "TERMINATED":
                    self.subnets.append(
                        Subnet(
                            id=subnet.id,
                            display_name=(
                                subnet.display_name
                                if hasattr(subnet, "display_name")
                                else ""
                            ),
                            compartment_id=compartment.id,
                            vcn_id=subnet.vcn_id,
                            cidr_block=(
                                subnet.cidr_block
                                if hasattr(subnet, "cidr_block")
                                else ""
                            ),
                            lifecycle_state=subnet.lifecycle_state,
                            region=region_key,
                            time_created=subnet.time_created,
                        )
                    )
        except Exception as error:
            logger.error(
                f"{region_key} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


# Service Models
class VCN(BaseModel):
    """OCI VCN model."""

    id: str
    display_name: str
    compartment_id: str
    cidr_blocks: list[str]
    lifecycle_state: str
    default_security_list_id: Optional[str]
    region: str
    time_created: datetime


class SecurityList(BaseModel):
    """OCI Security List model."""

    id: str
    display_name: str
    compartment_id: str
    vcn_id: str
    ingress_security_rules: list
    egress_security_rules: list
    lifecycle_state: str
    is_default: bool = False
    region: str
    time_created: datetime

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {object: lambda v: str(v)}


class NetworkSecurityGroup(BaseModel):
    """OCI Network Security Group model."""

    id: str
    display_name: str
    compartment_id: str
    vcn_id: str
    security_rules: list
    lifecycle_state: str
    region: str
    time_created: datetime

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {object: lambda v: str(v)}


class Subnet(BaseModel):
    """OCI Subnet model."""

    id: str
    display_name: str
    compartment_id: str
    vcn_id: str
    cidr_block: str
    lifecycle_state: str
    region: str
    time_created: datetime
