from alibabacloud_rds20140815 import models as rds_models
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.alibabacloud.lib.service.service import AlibabaCloudService


class RDS(AlibabaCloudService):
    """
    RDS (Relational Database Service) class for Alibaba Cloud.

    This class provides methods to interact with Alibaba Cloud RDS service
    to retrieve DB instances and their configurations.
    """

    def __init__(self, provider):
        # Call AlibabaCloudService's __init__
        super().__init__(__class__.__name__, provider, global_service=False)

        # Fetch RDS resources
        self.instances = []
        self.__threading_call__(self._describe_instances)

    def _describe_instances(self, regional_client):
        """List all RDS instances and fetch their details in a specific region."""
        region = getattr(regional_client, "region", "unknown")
        logger.info(f"RDS - Describing instances in {region}...")

        try:
            # DescribeDBInstances returns instance list
            request = rds_models.DescribeDBInstancesRequest()
            response = regional_client.describe_dbinstances(request)

            if response and response.body and response.body.items:
                for instance_data in response.body.items.dbinstance:
                    instance_id = getattr(instance_data, "dbinstance_id", "")

                    if not self.audit_resources or is_resource_filtered(
                        instance_id, self.audit_resources
                    ):

                        # Get additional information for specific checks
                        attribute_info = self._describe_db_instance_attribute(
                            regional_client, instance_id
                        )

                        # Check if SSL is enabled
                        ssl_status = self._describe_db_instance_ssl(
                            regional_client, instance_id
                        )

                        # Check TDE status
                        tde_status = self._describe_db_instance_tde(
                            regional_client, instance_id
                        )

                        # Check whitelist/security IPs
                        security_ips = self._describe_db_instance_ip_array(
                            regional_client, instance_id
                        )

                        # Check SQL audit status (SQL Explorer)
                        audit_status = self._describe_sql_collector_policy(
                            regional_client, instance_id
                        )

                        # Check parameters (log_connections, log_disconnections, log_duration)
                        parameters = self._describe_parameters(
                            regional_client, instance_id
                        )

                        self.instances.append(
                            DBInstance(
                                id=instance_id,
                                name=getattr(
                                    instance_data, "dbinstance_description", instance_id
                                ),
                                region=region,
                                engine=getattr(instance_data, "engine", ""),
                                engine_version=getattr(
                                    instance_data, "engine_version", ""
                                ),
                                status=getattr(instance_data, "dbinstance_status", ""),
                                type=getattr(instance_data, "dbinstance_type", ""),
                                net_type=getattr(
                                    instance_data, "dbinstance_net_type", ""
                                ),
                                connection_mode=getattr(
                                    instance_data, "connection_mode", ""
                                ),
                                public_connection_string=attribute_info.get(
                                    "ConnectionString", ""
                                ),
                                ssl_enabled=ssl_status.get("SSLEnabled", False),
                                tde_status=tde_status.get("TDEStatus", "Disabled"),
                                tde_key_id=tde_status.get("TDEKeyId", ""),
                                security_ips=security_ips,
                                audit_log_enabled=audit_status.get("StoragePeriod")
                                is not None,
                                audit_log_retention=audit_status.get(
                                    "StoragePeriod", 0
                                ),
                                log_connections=parameters.get(
                                    "log_connections", "off"
                                ),
                                log_disconnections=parameters.get(
                                    "log_disconnections", "off"
                                ),
                                log_duration=parameters.get("log_duration", "off"),
                            )
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_db_instance_attribute(
        self, regional_client, instance_id: str
    ) -> dict:
        """Get DB instance attributes including connection string."""
        try:
            request = rds_models.DescribeDBInstanceAttributeRequest()
            request.dbinstance_id = instance_id
            response = regional_client.describe_dbinstance_attribute(request)

            if (
                response
                and response.body
                and response.body.items
                and response.body.items.dbinstance_attribute
            ):
                # The response is a list, usually with one item
                attrs = response.body.items.dbinstance_attribute[0]
                return {"ConnectionString": getattr(attrs, "connection_string", "")}
            return {}
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return {}

    def _describe_db_instance_ssl(self, regional_client, instance_id: str) -> dict:
        """Check if SSL is enabled."""
        try:
            request = rds_models.DescribeDBInstanceSSLRequest()
            request.dbinstance_id = instance_id
            response = regional_client.describe_dbinstance_ssl(request)

            if response and response.body:
                # response.body is a DescribeDBInstanceSSLResponseBody model object, use getattr
                ssl_enabled = getattr(response.body, "sslenabled", "No")
                force_encryption = getattr(response.body, "force_encryption", "0")

                # SSL is enabled if SSLEnabled is "Yes" or ForceEncryption is "1"
                ssl_status = ssl_enabled == "Yes" or force_encryption == "1"
                return {"SSLEnabled": ssl_status}
            return {"SSLEnabled": False}
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            # Some instance types might not support SSL query
            return {"SSLEnabled": False}

    def _describe_db_instance_tde(self, regional_client, instance_id: str) -> dict:
        """Check TDE status."""
        try:
            request = rds_models.DescribeDBInstanceTDERequest()
            request.dbinstance_id = instance_id
            response = regional_client.describe_dbinstance_tde(request)

            if response and response.body:
                return {
                    "TDEStatus": getattr(response.body, "tdestatus", "Disabled"),
                }
            return {"TDEStatus": "Disabled"}
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return {"TDEStatus": "Disabled"}

    def _describe_db_instance_ip_array(self, regional_client, instance_id: str) -> list:
        """Get whitelist IP arrays."""
        try:
            request = rds_models.DescribeDBInstanceIPArrayListRequest()
            request.dbinstance_id = instance_id
            response = regional_client.describe_dbinstance_iparray_list(request)

            ips = []
            if response and response.body and response.body.items:
                for item in response.body.items.dbinstance_iparray:
                    security_ips = getattr(item, "security_ips", "")
                    if security_ips:
                        ips.extend(security_ips.split(","))
            return ips
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return []

    def _describe_sql_collector_policy(self, regional_client, instance_id: str) -> dict:
        """Check SQL audit status."""
        try:
            request = rds_models.DescribeSQLLogRecordsRequest()
            request.dbinstance_id = instance_id

            policy_request = rds_models.DescribeSQLCollectorPolicyRequest()
            policy_request.dbinstance_id = instance_id
            response = regional_client.describe_sqlcollector_policy(policy_request)

            if response and response.body:
                status = getattr(response.body, "sqlcollector_status", "")
                # storage_period is in days
                storage_period = getattr(response.body, "storage_period", 0)

                if status == "Enable":
                    return {"StoragePeriod": storage_period}

            return {}
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return {}

    def _describe_parameters(self, regional_client, instance_id: str) -> dict:
        """Get instance parameters."""
        try:
            request = rds_models.DescribeParametersRequest()
            request.dbinstance_id = instance_id
            response = regional_client.describe_parameters(request)

            params = {}
            if response and response.body and response.body.running_parameters:
                for param in response.body.running_parameters.dbinstance_parameter:
                    key = getattr(param, "parameter_name", "")
                    value = getattr(param, "parameter_value", "")
                    if key in ["log_connections", "log_disconnections", "log_duration"]:
                        params[key] = value.lower()

            return params
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return {}


class DBInstance(BaseModel):
    """RDS DB Instance model."""

    id: str
    name: str
    region: str
    engine: str
    engine_version: str
    status: str
    type: str
    net_type: str
    connection_mode: str
    public_connection_string: str
    ssl_enabled: bool
    tde_status: str
    tde_key_id: str
    security_ips: list
    audit_log_enabled: bool
    audit_log_retention: int  # in days
    log_connections: str
    log_disconnections: str
    log_duration: str
