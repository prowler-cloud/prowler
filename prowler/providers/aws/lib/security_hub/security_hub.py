from boto3 import session

from prowler.config.config import timestamp_utc
from prowler.lib.logger import logger
from prowler.lib.outputs.json import fill_json_asff
from prowler.lib.outputs.models import Check_Output_JSON_ASFF
from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

SECURITY_HUB_INTEGRATION_NAME = "prowler/prowler"
SECURITY_HUB_MAX_BATCH = 100


def prepare_security_hub_findings(
    findings: [], audit_info: AWS_Audit_Info, output_options, enabled_regions: []
) -> dict:
    security_hub_findings_per_region = {}

    # Create a key per audited region
    for region in enabled_regions:
        security_hub_findings_per_region[region] = []

    for finding in findings:
        # We don't send the MANUAL findings to AWS Security Hub
        if finding.status == "MANUAL":
            continue

        # We don't send findings to not enabled regions
        if finding.region not in enabled_regions:
            continue

        # Handle status filters, if any
        if not output_options.status or finding.status in output_options.status:
            continue

        # Get the finding region
        region = finding.region

        # Format the finding in the JSON ASFF format
        finding_json_asff = fill_json_asff(
            Check_Output_JSON_ASFF(), audit_info, finding, output_options
        )

        # Include that finding within their region in the JSON format
        security_hub_findings_per_region[region].append(
            finding_json_asff.dict(exclude_none=True)
        )

    return security_hub_findings_per_region


def verify_security_hub_integration_enabled_per_region(
    partition: str,
    region: str,
    session: session.Session,
    aws_account_number: str,
) -> bool:
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
            logger.error(
                f"Security Hub is enabled in {region} but Prowler integration does not accept findings. More info: https://docs.prowler.cloud/en/latest/tutorials/aws/securityhub/"
            )
        else:
            prowler_integration_enabled = True

    except Exception as error:
        logger.error(
            f"{error.__class__.__name__} -- [{error.__traceback__.tb_lineno}]:{error} in region {region}"
        )

    finally:
        return prowler_integration_enabled


def batch_send_to_security_hub(
    security_hub_findings_per_region: dict,
    session: session.Session,
) -> int:
    """
    send_to_security_hub sends findings to Security Hub and returns the number of findings that were successfully sent.
    """

    success_count = 0
    try:
        # Iterate findings by region
        for region, findings in security_hub_findings_per_region.items():
            # Send findings to Security Hub
            logger.info(f"Sending findings to Security Hub in the region {region}")

            security_hub_client = session.client("securityhub", region_name=region)

            success_count = __send_findings_to_security_hub__(
                findings, region, security_hub_client
            )

    except Exception as error:
        logger.error(
            f"{error.__class__.__name__} -- [{error.__traceback__.tb_lineno}]:{error} in region {region}"
        )
    return success_count


# Move previous Security Hub check findings to ARCHIVED (as prowler didn't re-detect them)
def resolve_security_hub_previous_findings(
    security_hub_findings_per_region: dict, audit_info: AWS_Audit_Info
) -> list:
    """
    resolve_security_hub_previous_findings archives all the findings that does not appear in the current execution
    """
    logger.info("Checking previous findings in Security Hub to archive them.")
    success_count = 0
    for region in security_hub_findings_per_region.keys():
        try:
            current_findings = security_hub_findings_per_region[region]
            # Get current findings IDs
            current_findings_ids = []
            for finding in current_findings:
                current_findings_ids.append(finding["Id"])
            # Get findings of that region
            security_hub_client = audit_info.audit_session.client(
                "securityhub", region_name=region
            )
            findings_filter = {
                "ProductName": [{"Value": "Prowler", "Comparison": "EQUALS"}],
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                "AwsAccountId": [
                    {"Value": audit_info.audited_account, "Comparison": "EQUALS"}
                ],
                "Region": [{"Value": region, "Comparison": "EQUALS"}],
            }
            get_findings_paginator = security_hub_client.get_paginator("get_findings")
            findings_to_archive = []
            for page in get_findings_paginator.paginate(Filters=findings_filter):
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
            success_count += __send_findings_to_security_hub__(
                findings_to_archive, region, security_hub_client
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__} -- [{error.__traceback__.tb_lineno}]:{error} in region {region}"
            )
    return success_count


def __send_findings_to_security_hub__(
    findings: [dict], region: str, security_hub_client
):
    """Private function send_findings_to_security_hub chunks the findings in groups of 100 findings and send them to AWS Security Hub. It returns the number of sent findings."""
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

    except Exception as error:
        logger.error(
            f"{error.__class__.__name__} -- [{error.__traceback__.tb_lineno}]:{error} in region {region}"
        )
    finally:
        return success_count
