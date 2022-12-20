import json
from itertools import groupby
from operator import itemgetter

from boto3 import session

from prowler.config.config import (
    json_asff_file_suffix,
    output_file_timestamp,
    timestamp_utc,
)
from prowler.lib.logger import logger
from prowler.lib.outputs.models import Check_Output_JSON_ASFF
from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info


def send_to_security_hub(
    region: str, finding_output: Check_Output_JSON_ASFF, session: session.Session
):
    try:
        logger.info("Sending findings to Security Hub.")
        # Check if security hub is enabled in current region
        security_hub_client = session.client("securityhub", region_name=region)
        security_hub_client.describe_hub()

        # Check if Prowler integration is enabled in Security Hub
        if "prowler/prowler" not in str(
            security_hub_client.list_enabled_products_for_import()
        ):
            logger.error(
                f"Security Hub is enabled in {region} but Prowler integration does not accept findings. More info: https://github.com/prowler-cloud/prowler/#security-hub-integration"
            )

        # Send finding to Security Hub
        batch_import = security_hub_client.batch_import_findings(
            Findings=[finding_output.dict()]
        )
        if batch_import["FailedCount"] > 0:
            failed_import = batch_import["FailedFindings"][0]
            logger.error(
                f"Failed to send archived findings to AWS Security Hub -- {failed_import['ErrorCode']} -- {failed_import['ErrorMessage']}"
            )

    except Exception as error:
        logger.error(f"{error.__class__.__name__} -- {error} in region {region}")


# Move previous Security Hub check findings to ARCHIVED (as prowler didn't re-detect them)
def resolve_security_hub_previous_findings(
    output_directory: str, audit_info: AWS_Audit_Info
) -> list:
    logger.info("Checking previous findings in Security Hub to archive them.")
    # Read current findings from json-asff file
    with open(
        f"{output_directory}/prowler-output-{audit_info.audited_account}-{output_file_timestamp}{json_asff_file_suffix}"
    ) as f:
        json_asff_file = json.load(f)

    # Sort by region
    json_asff_file = sorted(json_asff_file, key=itemgetter("ProductArn"))
    # Group by region
    for product_arn, current_findings in groupby(
        json_asff_file, key=itemgetter("ProductArn")
    ):
        region = product_arn.split(":")[3]
        try:
            # Check if security hub is enabled in current region
            security_hub_client = audit_info.audit_session.client(
                "securityhub", region_name=region
            )
            security_hub_client.describe_hub()
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
            list_chunked = [
                findings_to_archive[i : i + 100]
                for i in range(0, len(findings_to_archive), 100)
            ]
            for findings in list_chunked:
                batch_import = security_hub_client.batch_import_findings(
                    Findings=findings
                )
                if batch_import["FailedCount"] > 0:
                    failed_import = batch_import["FailedFindings"][0]
                    logger.error(
                        f"Failed to send archived findings to AWS Security Hub -- {failed_import['ErrorCode']} -- {failed_import['ErrorMessage']}"
                    )
        except Exception as error:
            logger.error(f"{error.__class__.__name__} -- {error} in region {region}")
