from boto3 import Session
from botocore.client import ClientError

from prowler.config.config import timestamp_utc
from prowler.lib.logger import logger
from prowler.lib.outputs.asff.asff import AWSSecurityFindingFormat

SECURITY_HUB_INTEGRATION_NAME = "prowler/prowler"
SECURITY_HUB_MAX_BATCH = 100


class SecurityHub:
    """
    Class representing a SecurityHub object for managing findings and interactions with AWS Security Hub.

    Attributes:
        _session (Session): AWS session object for authentication and communication with AWS services.
        _aws_account_id (str): AWS account ID associated with the SecurityHub instance.
        _aws_partition (str): AWS partition (e.g., aws, aws-cn, aws-us-gov) where SecurityHub is deployed.
        _findings_per_region (dict): Dictionary containing findings per region.
        _enabled_regions (dict): Dictionary containing enabled regions with SecurityHub clients.

    Methods:
        __init__: Initializes the SecurityHub object with necessary attributes.
        filter: Filters findings based on region, returning a dictionary with findings per region.
        verify_enabled_per_region: Verifies and stores enabled regions with SecurityHub clients.
        batch_send_to_security_hub: Sends findings to Security Hub and returns the count of successfully sent findings.
        archive_previous_findings: Archives findings that are not present in the current execution.
        _send_findings_to_security_hub: Sends findings to AWS Security Hub in batches and returns the count of successfully sent findings.
    """

    _session: Session
    _aws_account_id: str
    _aws_partition: str
    _findings_per_region: dict[str, list[AWSSecurityFindingFormat]]
    _enabled_regions: dict[str, Session]

    def __init__(
        self,
        aws_session: Session,
        aws_account_id: str,
        aws_partition: str,
        findings: list[AWSSecurityFindingFormat] = [],
        aws_security_hub_available_regions: list[str] = [],
        send_only_fails: bool = False,
    ) -> "SecurityHub":
        self._session = aws_session
        self._aws_account_id = aws_account_id
        self._aws_partition = aws_partition

        self._enabled_regions = None
        self._findings_per_region = {}

        if aws_security_hub_available_regions:
            self._enabled_regions = self.verify_enabled_per_region(
                aws_security_hub_available_regions
            )
        if findings and self._enabled_regions:
            self._findings_per_region = self.filter(findings, send_only_fails)

    def filter(
        self,
        findings: list[AWSSecurityFindingFormat],
        send_only_fails: bool,
    ) -> dict:
        """
        Filters the given list of findings based on the provided criteria and returns a dictionary containing findings per region.

        Args:
            findings (list[AWSSecurityFindingFormat]): List of findings to filter.
            send_only_fails (bool): Flag indicating whether to send only findings with status 'FAILED'.

        Returns:
            dict: A dictionary containing findings per region after applying the filtering criteria.
        """

        findings_per_region = {}
        try:
            # Create a key per audited region
            for region in self._enabled_regions.keys():
                findings_per_region[region] = []

            for finding in findings:
                # We don't send findings to not enabled regions
                if finding.Resources[0].Region not in findings_per_region:
                    continue

                if (
                    finding.Compliance.Status != "FAILED"
                    or finding.Compliance.Status == "WARNING"
                ) and send_only_fails:
                    continue

                # Get the finding region
                # We can do that since the finding always stores just one finding
                region = finding.Resources[0].Region

                # Include that finding within their region
                findings_per_region[region].append(finding)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__} -- [{error.__traceback__.tb_lineno}]: {error}"
            )
        return findings_per_region

    def verify_enabled_per_region(
        self,
        aws_security_hub_available_regions: list[str],
    ) -> dict[str, Session]:
        """
        Filters the given list of regions where AWS Security Hub is enabled and returns a dictionary containing the region and their boto3 client if the region and the Prowler integration is enabled.

        Args:
            aws_security_hub_available_regions (list[str]): List of AWS regions to check for Security Hub integration.

        Returns:
            dict: A dictionary containing enabled regions with SecurityHub clients.
        """
        enabled_regions = {}
        for region in aws_security_hub_available_regions:
            try:
                logger.info(
                    f"Checking if the {SECURITY_HUB_INTEGRATION_NAME} is enabled in the {region} region."
                )
                # Check if security hub is enabled in current region
                security_hub_client = self._session.client(
                    "securityhub", region_name=region
                )
                security_hub_client.describe_hub()

                # Check if Prowler integration is enabled in Security Hub
                security_hub_prowler_integration_arn = f"arn:{self._aws_partition}:securityhub:{region}:{self._aws_account_id}:product-subscription/{SECURITY_HUB_INTEGRATION_NAME}"
                if security_hub_prowler_integration_arn not in str(
                    security_hub_client.list_enabled_products_for_import()
                ):
                    logger.warning(
                        f"Security Hub is enabled in {region} but Prowler integration does not accept findings. More info: https://docs.prowler.cloud/en/latest/tutorials/aws/securityhub/"
                    )
                else:
                    enabled_regions[region] = self._session.client(
                        "securityhub", region_name=region
                    )

            # Handle all the permissions / configuration errors
            except ClientError as client_error:
                # Check if Account is subscribed to Security Hub
                error_code = client_error.response["Error"]["Code"]
                error_message = client_error.response["Error"]["Message"]
                if (
                    error_code == "InvalidAccessException"
                    and f"Account {self._aws_account_id} is not subscribed to AWS Security Hub"
                    in error_message
                ):
                    logger.warning(
                        f"{client_error.__class__.__name__} -- [{client_error.__traceback__.tb_lineno}]: {client_error}"
                    )
                else:
                    logger.error(
                        f"{client_error.__class__.__name__} -- [{client_error.__traceback__.tb_lineno}]: {client_error}"
                    )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__} -- [{error.__traceback__.tb_lineno}]: {error}"
                )
        return enabled_regions

    def batch_send_to_security_hub(
        self,
    ) -> int:
        """
        Sends the findings to AWS Security Hub in batches for each region and returns the count of successfully sent findings.

        Returns:
            int: Number of successfully sent findings to AWS Security Hub.
        """
        success_count = 0
        try:
            # Iterate findings by region
            for region, findings in self._findings_per_region.items():
                # Send findings to Security Hub
                logger.info(
                    f"Sending {len(findings)} findings to Security Hub in the region {region}"
                )

                # Convert findings to dict
                findings = [finding.dict(exclude_none=True) for finding in findings]
                success_count += self._send_findings_in_batches(
                    findings,
                    region,
                )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__} -- [{error.__traceback__.tb_lineno}]:{error} in region {region}"
            )
        return success_count

    def archive_previous_findings(self) -> int:
        """
        Checks previous findings in Security Hub to archive them.

        Returns:
            int: Number of successfully archived findings.
        """
        logger.info("Checking previous findings in Security Hub to archive them.")
        success_count = 0
        for region in self._findings_per_region.keys():
            try:
                current_findings = self._findings_per_region[region]
                # Get current findings IDs
                current_findings_ids = []
                for finding in current_findings:
                    current_findings_ids.append(finding.Id)
                # Get findings of that region
                findings_filter = {
                    "ProductName": [{"Value": "Prowler", "Comparison": "EQUALS"}],
                    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                    "AwsAccountId": [
                        {"Value": self._aws_account_id, "Comparison": "EQUALS"}
                    ],
                    "Region": [{"Value": region, "Comparison": "EQUALS"}],
                }
                get_findings_paginator = self._enabled_regions[region].get_paginator(
                    "get_findings"
                )
                findings_to_archive = []
                for page in get_findings_paginator.paginate(
                    Filters=findings_filter, PaginationConfig={"PageSize": 100}
                ):
                    # Archive findings that have not appear in this execution
                    for finding in page["Findings"]:
                        if finding["Id"] not in current_findings_ids:
                            finding["RecordState"] = "ARCHIVED"
                            finding["UpdatedAt"] = timestamp_utc.strftime(
                                "%Y-%m-%dT%H:%M:%SZ"
                            )

                            findings_to_archive.append(finding)
                logger.info(f"Archiving {len(findings_to_archive)} findings.")

                # Send archive findings to SHub
                success_count += self._send_findings_in_batches(
                    findings_to_archive,
                    region,
                )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__} -- [{error.__traceback__.tb_lineno}]:{error} in region {region}"
                )
        return success_count

    def _send_findings_in_batches(
        self, findings: list[AWSSecurityFindingFormat], region: str
    ) -> int:
        """
        Sends the given findings to AWS Security Hub in batches for a specific region and returns the count of successfully sent findings.

        Args:
            findings (list[AWSSecurityFindingFormat]): List of findings to send to AWS Security Hub.
            region (str): The AWS region where the findings will be sent.

        Returns:
            int: Number of successfully sent findings to AWS Security Hub.
        """
        success_count = 0
        try:
            list_chunked = [
                findings[i : i + SECURITY_HUB_MAX_BATCH]
                for i in range(0, len(findings), SECURITY_HUB_MAX_BATCH)
            ]
            for findings in list_chunked:
                batch_import = self._enabled_regions[region].batch_import_findings(
                    Findings=findings
                )
                if batch_import["FailedCount"] > 0:
                    failed_import = batch_import["FailedFindings"][0]
                    logger.error(
                        f"Failed to send findings to AWS Security Hub -- {failed_import['ErrorCode']} -- {failed_import['ErrorMessage']}"
                    )
                success_count += batch_import["SuccessCount"]
            return success_count
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__} -- [{error.__traceback__.tb_lineno}]:{error} in region {region}"
            )
            return success_count
