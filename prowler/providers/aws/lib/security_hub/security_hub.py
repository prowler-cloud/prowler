from boto3 import session
from botocore.client import ClientError

from prowler.config.config import timestamp_utc
from prowler.lib.logger import logger
from prowler.lib.outputs.asff.asff import AWSSecurityFindingFormat

SECURITY_HUB_INTEGRATION_NAME = "prowler/prowler"
SECURITY_HUB_MAX_BATCH = 100


def filter_security_hub_findings_per_region(
    findings: list[AWSSecurityFindingFormat],
    send_only_fails: bool,
    status: list,
    enabled_regions: list,
) -> dict:
    """filter_security_hub_findings_per_region filters the findings by region and status. It returns a dictionary with the findings per region.

    Args:
        findings (list[AWSSecurityFindingFormat]): List of findings
        send_only_fails (bool): Send only the findings that have failed
        status (list): List of statuses to filter the findings
        enabled_regions (list): List of enabled regions

    Returns:
        dict: Dictionary containing the findings per region
    """
    security_hub_findings_per_region = {}
    # Create a key per audited region
    for region in enabled_regions:
        security_hub_findings_per_region[region] = []
    for finding in findings:
        # We don't send findings to not enabled regions
        if finding.Resources[0].Region not in enabled_regions:
            continue

        if (
            finding.Compliance.Status != "FAILED"
            or finding.Compliance.Status == "WARNING"
        ) and send_only_fails:
            continue

        # SecurityHub valid statuses are: PASSED, FAILED, WARNING
        if status:
            if finding.Compliance.Status == "PASSED" and "PASS" not in status:
                continue
            if finding.Compliance.Status == "FAILED" and "FAIL" not in status:
                continue
            # Check muted finding
            if finding.Compliance.Status == "WARNING":
                continue

        # Get the finding region
        # We can do that since the finding always stores just one finding
        region = finding.Resources[0].Region

        # Include that finding within their region
        security_hub_findings_per_region[region].append(finding)

    return security_hub_findings_per_region


def verify_security_hub_integration_enabled_per_region(
    partition: str,
    region: str,
    session: session.Session,
    aws_account_number: str,
) -> bool:
    """
    verify_security_hub_integration_enabled_per_region returns True if the Prowler integration is enabled for the given region. Otherwise returns false.

    Args:
        partition (str): AWS partition
        region (str): AWS region
        session (session.Session): AWS session
        aws_account_number (str): AWS account number

    Returns:
        bool: True if the Prowler integration is enabled for the given region. Otherwise returns false.
    """
    f"""verify_security_hub_integration_enabled returns True if the {SECURITY_HUB_INTEGRATION_NAME} is enabled for the given region. Otherwise returns false."""
    prowler_integration_enabled = False

    try:
        logger.info(
            f"Checking if the {SECURITY_HUB_INTEGRATION_NAME} is enabled in the {region} region."
        )
        # Check if security hub is enabled in current region
        security_hub_client = session.client("securityhub", region_name=region)
        security_hub_client.describe_hub()

        # Check if Prowler integration is enabled in Security Hub
        security_hub_prowler_integration_arn = f"arn:{partition}:securityhub:{region}:{aws_account_number}:product-subscription/{SECURITY_HUB_INTEGRATION_NAME}"
        if security_hub_prowler_integration_arn not in str(
            security_hub_client.list_enabled_products_for_import()
        ):
            logger.warning(
                f"Security Hub is enabled in {region} but Prowler integration does not accept findings. More info: https://docs.prowler.cloud/en/latest/tutorials/aws/securityhub/"
            )
        else:
            prowler_integration_enabled = True

    # Handle all the permissions / configuration errors
    except ClientError as client_error:
        # Check if Account is subscribed to Security Hub
        error_code = client_error.response["Error"]["Code"]
        error_message = client_error.response["Error"]["Message"]
        if (
            error_code == "InvalidAccessException"
            and f"Account {aws_account_number} is not subscribed to AWS Security Hub"
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

    finally:
        return prowler_integration_enabled


def batch_send_to_security_hub(
    security_hub_findings_per_region: dict,
    session: session.Session,
) -> int:
    """
    batch_send_to_security_hub sends findings to Security Hub and returns the number of findings that were successfully sent.

    Args:
        security_hub_findings_per_region (dict): Dictionary containing the findings per region
        session (session.Session): AWS session

    Returns:
        int: Number of sent findings
    """

    success_count = 0
    try:
        # Iterate findings by region
        for region, findings in security_hub_findings_per_region.items():
            # Send findings to Security Hub
            logger.info(
                f"Sending {len(findings)} findings to Security Hub in the region {region}"
            )

            security_hub_client = session.client("securityhub", region_name=region)
            # Convert findings to dict
            findings = [finding.dict(exclude_none=True) for finding in findings]
            success_count += _send_findings_to_security_hub(
                findings, region, security_hub_client
            )

    except Exception as error:
        logger.error(
            f"{error.__class__.__name__} -- [{error.__traceback__.tb_lineno}]:{error} in region {region}"
        )
    return success_count


# Move previous Security Hub check findings to ARCHIVED (as prowler didn't re-detect them)
def resolve_security_hub_previous_findings(
    security_hub_findings_per_region: dict, provider
) -> int:
    """
    resolve_security_hub_previous_findings archives all the findings that does not appear in the current execution

    Args:
        security_hub_findings_per_region (dict): Dictionary containing the findings per region
        provider: Provider object

    Returns:
        int: Number of archived findings
    """
    logger.info("Checking previous findings in Security Hub to archive them.")
    success_count = 0
    for region in security_hub_findings_per_region.keys():
        try:
            current_findings = security_hub_findings_per_region[region]
            # Get current findings IDs
            current_findings_ids = []
            for finding in current_findings:
                current_findings_ids.append(finding.Id)
            # Get findings of that region
            security_hub_client = provider.session.current_session.client(
                "securityhub", region_name=region
            )
            findings_filter = {
                "ProductName": [{"Value": "Prowler", "Comparison": "EQUALS"}],
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                "AwsAccountId": [
                    {"Value": provider.identity.account, "Comparison": "EQUALS"}
                ],
                "Region": [{"Value": region, "Comparison": "EQUALS"}],
            }
            get_findings_paginator = security_hub_client.get_paginator("get_findings")
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
            success_count += _send_findings_to_security_hub(
                findings_to_archive, region, security_hub_client
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__} -- [{error.__traceback__.tb_lineno}]:{error} in region {region}"
            )
    return success_count


def _send_findings_to_security_hub(
    findings: list[dict], region: str, security_hub_client
) -> int:
    """Private function send_findings_to_security_hub chunks the findings in groups of 100 findings and send them to AWS Security Hub. It returns the number of sent findings.

    Args:
        findings (list[dict]): List of findings to send to AWS Security Hub
        region (str): AWS region to send the findings
        security_hub_client: AWS Security Hub client

    Returns:
        int: Number of sent findings
    """
    success_count = 0
    try:
        list_chunked = [
            findings[i : i + SECURITY_HUB_MAX_BATCH]
            for i in range(0, len(findings), SECURITY_HUB_MAX_BATCH)
        ]
        for findings in list_chunked:
            batch_import = security_hub_client.batch_import_findings(Findings=findings)
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
