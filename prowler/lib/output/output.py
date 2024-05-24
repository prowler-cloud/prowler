import sys
from typing import Any

from boto3.session import Session
from botocore.client import ClientError
from slack_sdk import WebClient

from prowler.config.config import (
    aws_logo,
    azure_logo,
    csv_file_suffix,
    gcp_logo,
    json_asff_file_suffix,
    json_ocsf_file_suffix,
    square_logo_img,
    timestamp_utc,
)
from prowler.lib.check.models import Check_Report
from prowler.lib.logger import logger
from prowler.lib.outputs.compliance.compliance import get_check_compliance
from prowler.lib.outputs.json_asff.models import (
    Check_Output_JSON_ASFF,
    Compliance,
    ProductFields,
    Recommendation,
    Remediation,
    Resource,
    Severity,
)
from prowler.lib.utils.utils import hash_sha512
from prowler.providers.aws.lib.security_hub.security_hub import (
    SECURITY_HUB_INTEGRATION_NAME,
    SECURITY_HUB_MAX_BATCH,
)
from prowler.providers.common.provider import Provider


# TODO: Child classes of JSON_ASFF, JSON_OCSF, CSV, COMPLIANCE
class Output:
    _provider: Provider
    _stats: dict[str, Any]

    def __init__(self, provider: Provider, findings: list[Check_Report]) -> "Output":
        self._provider = provider
        self._findings = findings
        self._stats = self.__get_stats__(findings)

    @property
    def provider(self):
        return self._provider

    @property
    def findings(self):
        return self._findings

    @property
    def stats(self):
        return self._stats

    def __get_stats__(self, findings: list[Check_Report]) -> dict[str, int]:
        """
        Extracts the audit statistics from the checks findings.
        Args:
            findings: list of Check_Report objects
        Returns:
            dict: dictionary with the audit statistics with the following keys:
                - total_pass: total number of passed checks
                - total_fail: total number of failed checks
                - resources_count: total number of resources scanned
                - findings_count: total number of findings
                - all_fails_are_muted: boolean indicating if all the failed checks are muted
        """
        logger.info("Extracting audit statistics...")
        stats = {}
        total_pass = 0
        total_fail = 0
        resources = set()
        findings_count = 0
        all_fails_are_muted = True

        for finding in findings:
            # Save the resource_id
            resources.add(finding.resource_id)
            if finding.status == "PASS":
                total_pass += 1
                findings_count += 1
            if finding.status == "FAIL":
                total_fail += 1
                findings_count += 1
                if not finding.muted and all_fails_are_muted:
                    all_fails_are_muted = False

        stats["total_pass"] = total_pass
        stats["total_fail"] = total_fail
        stats["resources_count"] = len(resources)
        stats["findings_count"] = findings_count
        stats["all_fails_are_muted"] = all_fails_are_muted

        return stats

    class JSON_ASFF:

        def __init__(self, finding: Check_Report) -> "Check_Output_JSON_ASFF":
            return self.__convert__(finding)

        def __convert__(self, finding) -> Check_Output_JSON_ASFF:
            """
            Fill the finding's output in JSON ASFF format.

            Parameters:
            - provider: The provider object containing information about the provider (e.g., AWS) and the output options object containing information about the desired output format.
            - finding: The finding object containing information about the specific finding.

            Returns:
            - finding_output: The filled finding's output in JSON ASFF format.
            """

            try:
                # Check if there are no resources in the finding
                if finding.resource_arn == "":
                    if finding.resource_id == "":
                        finding.resource_id = "NONE_PROVIDED"
                    finding.resource_arn = finding.resource_id

                timestamp = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
                resource_tags = self.__generate_json_asff_resource_tags__(
                    finding.resource_tags
                )

                # Iterate for each compliance framework
                compliance_summary = []
                associated_standards = []
                check_compliance = get_check_compliance(
                    finding, Output.provider.type, Output.provider.output_options
                )
                for key, value in check_compliance.items():
                    if (
                        len(associated_standards) < 20
                    ):  # AssociatedStandards should NOT have more than 20 items
                        associated_standards.append({"StandardsId": key})
                        item = f"{key} {' '.join(value)}"
                        if len(item) > 64:
                            item = item[0:63]
                        compliance_summary.append(item)

                # Ensures finding_status matches allowed values in ASFF
                finding_status = self.__generate_json_asff_status__(
                    finding.status, finding.muted
                )

                json_asff_output = Check_Output_JSON_ASFF(
                    # The following line cannot be changed because it is the format we use to generate unique findings for AWS Security Hub
                    # If changed some findings could be lost because the unique identifier will be different
                    # TODO: get this from the provider output
                    Id=f"prowler-{finding.check_metadata.CheckID}-{Output.provider.identity.account}-{finding.region}-{hash_sha512(finding.resource_id)}",
                    ProductArn=f"arn:{Output.provider.identity.partition}:securityhub:{finding.region}::product/prowler/prowler",
                    ProductFields=ProductFields(
                        ProwlerResourceName=finding.resource_arn,
                    ),
                    GeneratorId="prowler-" + finding.check_metadata.CheckID,
                    AwsAccountId=Output.provider.identity.account,
                    Types=finding.check_metadata.CheckType,
                    FirstObservedAt=timestamp,
                    UpdatedAt=timestamp,
                    CreatedAt=timestamp,
                    Severity=Severity(Label=finding.check_metadata.Severity.upper()),
                    Title=finding.check_metadata.CheckTitle,
                    Description=finding.status_extended,
                    Resources=[
                        Resource(
                            Id=finding.resource_arn,
                            Type=finding.check_metadata.ResourceType,
                            Partition=Output.provider.identity.partition,
                            Region=finding.region,
                            Tags=resource_tags,
                        )
                    ],
                    Compliance=Compliance(
                        Status=finding_status,
                        AssociatedStandards=associated_standards,
                        RelatedRequirements=compliance_summary,
                    ),
                    Remediation=Remediation(
                        Recommendation=Recommendation(
                            Text=finding.check_metadata.Remediation.Recommendation.Text,
                            Url=finding.check_metadata.Remediation.Recommendation.Url,
                        )
                    ),
                )
                return json_asff_output
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        def __generate_json_asff_status__(status: str, muted: bool = False) -> str:
            json_asff_status = ""
            if muted:
                # Per AWS Security Hub "MUTED" is not a valid status
                # https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_Compliance.html
                json_asff_status = "WARNING"
            else:
                if status == "PASS":
                    json_asff_status = "PASSED"
                elif status == "FAIL":
                    json_asff_status = "FAILED"
                else:
                    json_asff_status = "NOT_AVAILABLE"

            return json_asff_status

        def __generate_json_asff_resource_tags__(tags):
            try:
                resource_tags = {}
                if tags and tags != [None]:
                    for tag in tags:
                        if "Key" in tag and "Value" in tag:
                            resource_tags[tag["Key"]] = tag["Value"]
                        else:
                            resource_tags.update(tag)
                    if len(resource_tags) == 0:
                        return None
                else:
                    return None
                return resource_tags
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    class S3:
        _aws_session: Session

        def __init__(self, aws_session: Session) -> "Output.S3":
            self._aws_session = aws_session

        @property
        def _aws_session(self):
            return self._aws_session

        def send(self, filename: str, directory: str, mode: str, bucket_name: str):
            """
            Sends the output file to the S3 bucket.
            Args:
                filename: name of the output file.
                directory: directory where the output file is located.
                mode: output mode (csv, json-asff, json-ocsf, compliance).
                bucket_name: S3 bucket name where the output file will be uploaded.
            """
            try:
                # S3 Object name
                bucket_directory = self.__get_s3_object_path__(directory)
                filename = ""
                # Get only last part of the path
                if mode in ["csv", "json-asff", "json-ocsf"]:
                    if mode == "csv":
                        filename = f"{filename}{csv_file_suffix}"
                    elif mode == "json-asff":
                        filename = f"{filename}{json_asff_file_suffix}"
                    elif mode == "json-ocsf":
                        filename = f"{filename}{json_ocsf_file_suffix}"
                    file_name = directory + "/" + filename
                    object_name = bucket_directory + "/" + mode + "/" + filename
                else:  # Compliance output mode
                    filename = f"{filename}_{mode}{csv_file_suffix}"
                    file_name = directory + "/compliance/" + filename
                    object_name = bucket_directory + "/compliance/" + filename

                logger.info(
                    f"Sending output file {filename} to S3 bucket {bucket_name}"
                )

                s3_client = self._aws_session.client("s3")
                s3_client.upload_file(file_name, bucket_name, object_name)

            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                )

        def __get_s3_object_path__(directory: str) -> str:
            """
            Returns the S3 object path.
            Args:
                directory: directory where the output file is located.
            Returns:
                str: S3 object path.
            """
            bucket_remote_dir = directory
            if "prowler/" in bucket_remote_dir:  # Check if it is not a custom directory
                bucket_remote_dir = bucket_remote_dir.partition("prowler/")[-1]

            return bucket_remote_dir

    class SecurityHub:
        _aws_session: Session

        def __init__(self, aws_session: Session) -> "Output.SecurityHub":
            self._aws_session = aws_session
            self.findings_per_region = {}

        @property
        def _aws_session(self):
            return self._aws_session

        @property
        def _findings_per_region(self):
            return self.findings_per_region

        def prepare(self, enabled_regions: list) -> dict:
            """
            Prepare the findings to be sent to AWS Security Hub.
            Args:
                enabled_regions: list of enabled regions.
            Returns:
                dict: dictionary with the findings per region.
            """
            findings_per_region = {}
            try:
                # Create a key per audited region
                # TODO: Parse all regions and filter the region you want to send the findings in the send funtion?
                for region in enabled_regions:
                    findings_per_region[region] = []

                for finding in Output.findings:
                    # We don't send the MANUAL findings to AWS Security Hub
                    if finding.status == "MANUAL":
                        continue

                    # We don't send findings to not enabled regions
                    if finding.region not in enabled_regions:
                        continue

                    if (
                        finding.status != "FAIL" or finding.muted
                    ) and Output.provider.output_options.send_sh_only_fails:
                        continue

                    if Output.provider.output_options.status:
                        if finding.status not in Output.provider.output_options.status:
                            continue

                        if finding.muted:
                            continue

                    # Get the finding region
                    region = finding.region

                    # Format the finding in the JSON ASFF format
                    # TODO: Output.JSON_ASFF
                    finding_json_asff = Output.JSON_ASFF(finding)

                    # Include that finding within their region in the JSON format
                    findings_per_region[region].append(
                        finding_json_asff.dict(exclude_none=True)
                    )

                self.findings_per_region = findings_per_region

            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__} -- [{error.__traceback__.tb_lineno}]:{error} in region {region}"
                )

        def send(
            self,
        ) -> int:
            """
            Send the findings to AWS Security Hub.
            Returns:
                int: number of findings successfully sent to AWS Security Hub.
            """

            success_count = 0
            try:
                # Iterate findings by region
                for region, findings in self.findings_per_region.items():
                    # Send findings to Security Hub
                    logger.info(
                        f"Sending findings to Security Hub in the region {region}"
                    )

                    security_hub_client = self._aws_session.client(
                        "securityhub", region_name=region
                    )

                    success_count = self.__batch_import_findings__(
                        findings, region, security_hub_client
                    )

            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__} -- [{error.__traceback__.tb_lineno}]:{error} in region {region}"
                )
            return success_count

        def resolve(self) -> list:
            """
            resolve archives all the findings that does not appear in the current execution

            """
            logger.info("Checking previous findings in Security Hub to archive them.")
            success_count = 0
            for region in self.findings_per_region.keys():
                try:
                    current_findings = self.findings_per_region[region]
                    # Get current findings IDs
                    current_findings_ids = []
                    for finding in current_findings:
                        current_findings_ids.append(finding["Id"])
                    # Get findings of that region
                    security_hub_client = self._aws_session.client(
                        "securityhub", region_name=region
                    )
                    findings_filter = {
                        "ProductName": [{"Value": "Prowler", "Comparison": "EQUALS"}],
                        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                        "AwsAccountId": [
                            {
                                "Value": Output.provider.identity.account,
                                "Comparison": "EQUALS",
                            }
                        ],
                        "Region": [{"Value": region, "Comparison": "EQUALS"}],
                    }
                    get_findings_paginator = security_hub_client.get_paginator(
                        "get_findings"
                    )
                    findings_to_archive = []
                    for page in get_findings_paginator.paginate(
                        Filters=findings_filter
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
                    success_count += self.__batch_import_findings__(
                        findings_to_archive, region, security_hub_client
                    )
                except Exception as error:
                    logger.error(
                        f"{error.__class__.__name__} -- [{error.__traceback__.tb_lineno}]:{error} in region {region}"
                    )
            return success_count

        def verify(
            self,
            partition: str,
            region: str,
            aws_account_number: str,
        ) -> bool:
            f"""
            verify_security_hub_integration_enabled checks if the {SECURITY_HUB_INTEGRATION_NAME} is enabled in the given region.
            Args:
                partition: AWS partition (aws, aws-cn, aws-us-gov).
                region: AWS region.
                aws_account_number: AWS account number.
            Returns:
                bool: True if the {SECURITY_HUB_INTEGRATION_NAME} is enabled in the given region. Otherwise returns false.
            """
            prowler_integration_enabled = False
            try:
                logger.info(
                    f"Checking if the {SECURITY_HUB_INTEGRATION_NAME} is enabled in the {region} region."
                )
                # Check if security hub is enabled in current region
                security_hub_client = self._aws_session.client(
                    "securityhub", region_name=region
                )
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

        def __batch_import_findings__(
            findings: list[dict], region: str, security_hub_client
        ) -> int:
            """Private function batch_import_findings chunks the findings in groups of 100 findings and send them to AWS Security Hub.
            Args:
                findings: list of findings in JSON format.
                region: AWS region.
                security_hub_client: AWS Security Hub client.
            Returns:
                int: number of findings successfully sent to AWS Security Hub.
            """
            success_count = 0
            try:
                list_chunked = [
                    findings[i : i + SECURITY_HUB_MAX_BATCH]
                    for i in range(0, len(findings), SECURITY_HUB_MAX_BATCH)
                ]

                for findings in list_chunked:
                    batch_import = security_hub_client.batch_import_findings(
                        Findings=findings
                    )
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

    class Slack:
        _token: str
        _channel: str

        def __init__(self, token: str, channel: str) -> "Output.Slack":
            self._token = token
            self._channel = channel

        @property
        def token(self):
            return self._token

        @property
        def channel(self):
            return self._channel

        def send(self) -> Any:
            """
            Sends the findings to Slack.
            Returns:
                Any: Slack response.
            """
            try:
                client = WebClient(token=self.token)
                identity, logo = self.__create_message_identity__(Output.provider)
                response = client.chat_postMessage(
                    username="Prowler",
                    icon_url=square_logo_img,
                    channel=f"#{self.channel}",
                    blocks=self.__create_message_blocks__(identity, logo, Output.stats),
                )
                return response
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        def __create_message_identity__(self, provider):
            """
            Create a Slack message identity based on the provider type.

            Parameters:
            - provider (Provider): The Provider (e.g. "AwsProvider", "GcpProvider", "AzureProvide").

            Returns:
            - identity (str): The message identity based on the provider type.
            - logo (str): The logo URL associated with the provider type.
            """
            try:
                identity = ""
                logo = aws_logo
                if provider.type == "aws":
                    identity = f"AWS Account *{provider.identity.account}*"
                elif provider.type == "gcp":
                    identity = f"GCP Projects *{', '.join(provider.project_ids)}*"
                    logo = gcp_logo
                elif provider.type == "azure":
                    printed_subscriptions = []
                    for key, value in provider.identity.subscriptions.items():
                        intermediate = f"- *{key}: {value}*\n"
                        printed_subscriptions.append(intermediate)
                    identity = f"Azure Subscriptions:\n{''.join(printed_subscriptions)}"
                    logo = azure_logo
                return identity, logo
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        def __create_message_blocks__(self, identity, logo, stats) -> list:
            """
            Create the Slack message blocks.
            Args:
                identity: message identity.
                logo: logo URL.
                stats: audit statistics.
            Returns:
                list: list of Slack message blocks.
            """
            try:
                blocks = [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": self.__create_title__(identity, stats),
                        },
                        "accessory": {
                            "type": "image",
                            "image_url": logo,
                            "alt_text": "Provider Logo",
                        },
                    },
                    {"type": "divider"},
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"\n:white_check_mark: *{stats['total_pass']} Passed findings* ({round(stats['total_pass'] / stats['findings_count'] * 100 , 2)}%)\n",
                        },
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"\n:x: *{stats['total_fail']} Failed findings* ({round(stats['total_fail'] / stats['findings_count'] * 100 , 2)}%)\n ",
                        },
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"\n:bar_chart: *{stats['resources_count']} Scanned Resources*\n",
                        },
                    },
                    {"type": "divider"},
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": f"Used parameters: `prowler {' '.join(sys.argv[1:])} `",
                            }
                        ],
                    },
                    {"type": "divider"},
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": "Join our Slack Community!"},
                        "accessory": {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Prowler :slack:"},
                            "url": "https://join.slack.com/t/prowler-workspace/shared_invite/zt-1hix76xsl-2uq222JIXrC7Q8It~9ZNog",
                        },
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "Feel free to contact us in our repo",
                        },
                        "accessory": {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Prowler :github:"},
                            "url": "https://github.com/prowler-cloud/prowler",
                        },
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "See all the things you can do with ProwlerPro",
                        },
                        "accessory": {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Prowler Pro"},
                            "url": "https://prowler.pro",
                        },
                    },
                ]
                return blocks
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        def __create_title__(self, identity, stats) -> str:
            """
            Create the Slack message title.
            Args:
                identity: message identity.
                stats: audit statistics.
            Returns:
                str: Slack message title.
            """
            try:
                title = f"Hey there 👋 \n I'm *Prowler*, _the handy multi-cloud security tool_ :cloud::key:\n\n I have just finished the security assessment on your {identity} with a total of *{stats['findings_count']}* findings."
                return title
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
