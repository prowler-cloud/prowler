from typing import Optional

from botocore.client import ClientError
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class Config(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.recorders = {}
        self.aggregators: dict[str, list] = {}
        self.delegated_administrators: list = []
        self.delegated_administrators_lookup_failed: bool = False
        self.__threading_call__(self.describe_configuration_recorders)
        self.__threading_call__(
            self._describe_configuration_recorder_status, self.recorders.values()
        )
        self.__threading_call__(self._describe_configuration_aggregators)
        # Organizations API is not regional; single call.
        self._list_config_delegated_administrators()

    def _get_recorder_arn_template(self, region):
        return f"arn:{self.audited_partition}:config:{region}:{self.audited_account}:recorder"

    def describe_configuration_recorders(self, regional_client):
        logger.info("Config - Listing Recorders...")
        try:
            recorders = regional_client.describe_configuration_recorders().get(
                "ConfigurationRecorders", []
            )

            # No config recorders in region
            if not recorders:
                self.recorders[regional_client.region] = Recorder(
                    name=self.audited_account,
                    role_arn="",
                    region=regional_client.region,
                )
            else:
                for recorder in recorders:
                    if not self.audit_resources or (
                        is_resource_filtered(recorder["name"], self.audit_resources)
                    ):
                        self.recorders[recorder["name"]] = Recorder(
                            name=recorder["name"],
                            role_arn=recorder["roleARN"],
                            region=regional_client.region,
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_configuration_recorder_status(self, recorder):
        logger.info("Config - Listing Recorders Status...")
        try:
            if recorder.name != self.audited_account:
                recorder_status = (
                    self.regional_clients[recorder.region]
                    .describe_configuration_recorder_status(
                        ConfigurationRecorderNames=[recorder.name]
                    )
                    .get("ConfigurationRecordersStatus", [])
                )

                if recorder_status:
                    recorder.recording = recorder_status[0].get("recording", False)
                    recorder.last_status = recorder_status[0].get(
                        "lastStatus", "Failure"
                    )

        except Exception as error:
            logger.error(
                f"{recorder.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_configuration_aggregators(self, regional_client):
        """Describe AWS Config configuration aggregators per region.

        An aggregator counts as organization-aware when its
        OrganizationAggregationSource key is present in the response.
        """
        logger.info("Config - Describing Configuration Aggregators...")
        try:
            paginator = regional_client.get_paginator(
                "describe_configuration_aggregators"
            )
            region_aggregators: list = []
            for page in paginator.paginate():
                for aggregator in page.get("ConfigurationAggregators", []):
                    name = aggregator.get("ConfigurationAggregatorName", "")
                    arn = aggregator.get("ConfigurationAggregatorArn", "")
                    org_source = aggregator.get("OrganizationAggregationSource")
                    org_aware = org_source is not None
                    all_aws_regions = False
                    aws_regions: Optional[list] = None
                    if org_aware:
                        all_aws_regions = org_source.get("AllAwsRegions", False)
                        aws_regions = org_source.get("AwsRegions")
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        region_aggregators.append(
                            Aggregator(
                                name=name,
                                arn=arn,
                                region=regional_client.region,
                                all_aws_regions=all_aws_regions,
                                aws_regions=aws_regions,
                                organization_aggregation_source_present=org_aware,
                            )
                        )
            if region_aggregators:
                self.aggregators[regional_client.region] = region_aggregators
        except ClientError as error:
            if error.response["Error"]["Code"] in (
                "AccessDeniedException",
                "AccessDenied",
            ):
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

    def _list_config_delegated_administrators(self):
        """List delegated administrators for the AWS Config service principal.

        Uses the Organizations API directly (not regional). Sets
        delegated_administrators_lookup_failed to True on AccessDenied so callers
        can surface the unknown delegated-admin state in findings.
        """
        logger.info(
            "Config - Listing delegated administrators for config.amazonaws.com..."
        )
        try:
            org_client = self.session.client("organizations")
            paginator = org_client.get_paginator("list_delegated_administrators")
            for page in paginator.paginate(ServicePrincipal="config.amazonaws.com"):
                for admin in page.get("DelegatedAdministrators", []):
                    self.delegated_administrators.append(
                        ConfigDelegatedAdministrator(
                            id=admin.get("Id", ""),
                            arn=admin.get("Arn", ""),
                            name=admin.get("Name", ""),
                            email=admin.get("Email", ""),
                            status=admin.get("Status", ""),
                            joined_method=admin.get("JoinedMethod", ""),
                        )
                    )
        except ClientError as error:
            error_code = error.response["Error"]["Code"]
            if error_code in (
                "AccessDeniedException",
                "AccessDenied",
                "AWSOrganizationsNotInUseException",
            ):
                self.delegated_administrators_lookup_failed = True
                logger.warning(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Recorder(BaseModel):
    name: str
    role_arn: str
    recording: Optional[bool]
    last_status: Optional[str]
    region: str


class Aggregator(BaseModel):
    """Represents an AWS Config Configuration Aggregator."""

    name: str
    arn: str
    region: str
    all_aws_regions: bool = False
    aws_regions: Optional[list] = None
    organization_aggregation_source_present: bool = False


class ConfigDelegatedAdministrator(BaseModel):
    """Represents a delegated administrator registered for config.amazonaws.com."""

    id: str
    arn: str
    name: str
    email: str
    status: str
    joined_method: str
