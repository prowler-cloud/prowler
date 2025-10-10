"""OCI Kms Service Module."""

from typing import Optional

import oci
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.oraclecloud.lib.service.service import OCIService


class Kms(OCIService):
    """OCI Kms Service class."""

    def __init__(self, provider):
        """Initialize the Kms service."""
        super().__init__("kms", provider)
        self.keys = []
        self.__threading_call__(self.__list_keys__)

    def __get_client__(self, region):
        """Get the Kms client for a region."""
        client_region = self.regional_clients.get(region)
        if client_region:
            return self._create_oci_client(oci.key_management.KmsVaultClient)
        return None

    def __list_keys__(self, regional_client):
        """List all keys."""
        try:
            vault_client = self.__get_client__(regional_client.region)
            if not vault_client:
                return

            logger.info(f"Kms - Listing keys in {regional_client.region}...")

            for compartment in self.audited_compartments:
                try:
                    # First, list all vaults in this compartment
                    vaults = oci.pagination.list_call_get_all_results(
                        vault_client.list_vaults, compartment_id=compartment.id
                    ).data

                    for vault in vaults:
                        # Only process vaults in ACTIVE state
                        if vault.lifecycle_state == "ACTIVE":
                            # Get the management endpoint for this vault
                            management_endpoint = vault.management_endpoint

                            # Create KMS management client for this vault's endpoint
                            # KmsManagementClient requires service_endpoint, so create it directly
                            if self.session_signer:
                                kms_management_client = (
                                    oci.key_management.KmsManagementClient(
                                        config=self.session_config,
                                        signer=self.session_signer,
                                        service_endpoint=management_endpoint,
                                    )
                                )
                            else:
                                kms_management_client = (
                                    oci.key_management.KmsManagementClient(
                                        config=self.session_config,
                                        service_endpoint=management_endpoint,
                                    )
                                )

                            # List keys in this vault
                            keys = oci.pagination.list_call_get_all_results(
                                kms_management_client.list_keys,
                                compartment_id=compartment.id,
                            ).data

                            for key_summary in keys:
                                if key_summary.lifecycle_state == "ENABLED":
                                    # Get full key details to get rotation info
                                    key_details = kms_management_client.get_key(
                                        key_id=key_summary.id
                                    ).data

                                    self.keys.append(
                                        Key(
                                            id=key_details.id,
                                            name=(
                                                key_details.display_name
                                                if hasattr(key_details, "display_name")
                                                else key_details.id
                                            ),
                                            compartment_id=compartment.id,
                                            region=regional_client.region,
                                            lifecycle_state=key_details.lifecycle_state,
                                            is_auto_rotation_enabled=(
                                                key_details.is_auto_rotation_enabled
                                                if hasattr(
                                                    key_details,
                                                    "is_auto_rotation_enabled",
                                                )
                                                else False
                                            ),
                                            rotation_interval_in_days=(
                                                key_details.auto_key_rotation_details.rotation_interval_in_days
                                                if hasattr(
                                                    key_details,
                                                    "auto_key_rotation_details",
                                                )
                                                and key_details.auto_key_rotation_details
                                                and hasattr(
                                                    key_details.auto_key_rotation_details,
                                                    "rotation_interval_in_days",
                                                )
                                                else None
                                            ),
                                        )
                                    )
                except Exception as error:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                    continue
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


# Service Models
class Key(BaseModel):
    """Key model."""

    id: str
    name: str
    compartment_id: str
    region: str
    lifecycle_state: str
    is_auto_rotation_enabled: bool = False
    rotation_interval_in_days: Optional[int] = None
