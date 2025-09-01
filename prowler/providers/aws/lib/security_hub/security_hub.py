import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional, Union

from boto3 import Session
from botocore.client import ClientError
from botocore.exceptions import NoCredentialsError, ProfileNotFound

from prowler.config.config import timestamp_utc
from prowler.lib.logger import logger
from prowler.lib.outputs.asff.asff import AWSSecurityFindingFormat
from prowler.providers.aws.aws_provider import AwsProvider
from prowler.providers.aws.config import (
    AWS_STS_GLOBAL_ENDPOINT_REGION,
    ROLE_SESSION_NAME,
)
from prowler.providers.aws.exceptions.exceptions import (
    AWSAccessKeyIDInvalidError,
    AWSArgumentTypeValidationError,
    AWSAssumeRoleError,
    AWSIAMRoleARNEmptyResourceError,
    AWSIAMRoleARNInvalidAccountIDError,
    AWSIAMRoleARNInvalidResourceTypeError,
    AWSIAMRoleARNPartitionEmptyError,
    AWSIAMRoleARNRegionNotEmtpyError,
    AWSIAMRoleARNServiceNotIAMnorSTSError,
    AWSNoCredentialsError,
    AWSProfileNotFoundError,
    AWSSecretAccessKeyInvalidError,
    AWSSessionTokenExpiredError,
    AWSSetUpSessionError,
)
from prowler.providers.aws.lib.arguments.arguments import (
    validate_role_session_name,
    validate_session_duration,
)
from prowler.providers.aws.lib.arn.arn import parse_iam_credentials_arn
from prowler.providers.aws.lib.security_hub.exceptions.exceptions import (
    SecurityHubInvalidRegionError,
    SecurityHubNoEnabledRegionsError,
)
from prowler.providers.aws.lib.session.aws_set_up_session import AwsSetUpSession
from prowler.providers.aws.models import AWSAssumeRoleInfo
from prowler.providers.common.models import Connection

SECURITY_HUB_INTEGRATION_NAME = "prowler/prowler"
SECURITY_HUB_MAX_BATCH = 100


@dataclass
class SecurityHubConnection(Connection):
    """
    Represents a Security Hub connection object.
    Attributes:
        enabled_regions (set): Set of regions where Security Hub is enabled.
        disabled_regions (set): Set of regions where Security Hub is disabled.
        partition (str): AWS partition (e.g., aws, aws-cn, aws-us-gov) where SecurityHub is deployed.
    """

    enabled_regions: set = None
    disabled_regions: set = None
    partition: str = ""


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
        aws_account_id: str,
        aws_partition: str = None,
        aws_session: Session = None,
        findings: list[AWSSecurityFindingFormat] = [],
        aws_security_hub_available_regions: list[str] = [],
        send_only_fails: bool = False,
        role_arn: str = None,
        session_duration: int = 3600,
        external_id: str = None,
        role_session_name: str = ROLE_SESSION_NAME,
        mfa: bool = None,
        profile: str = None,
        aws_access_key_id: str = None,
        aws_secret_access_key: str = None,
        aws_session_token: Optional[str] = None,
        retries_max_attempts: int = 3,
        regions: set = set(),
    ) -> "SecurityHub":
        """
        Initializes the SecurityHub object with the necessary attributes.

        Args:
        - aws_session (Session): AWS session object for authentication and communication with AWS services.
        - aws_account_id (str): AWS account ID associated with the SecurityHub instance.
        - aws_partition (str): AWS partition (e.g., aws, aws-cn, aws-us-gov) where SecurityHub is deployed.
        - findings (list[AWSSecurityFindingFormat]): List of findings to filter and send to Security Hub.
        - aws_security_hub_available_regions (list[str]): List of regions where Security Hub is available.
        - send_only_fails (bool): Flag indicating whether to send only findings with status 'FAIL'.
        - role_arn: The ARN of the IAM role to assume.
        - session_duration: The duration of the session in seconds, between 900 and 43200.
        - external_id: The external ID to use when assuming the IAM role.
        - role_session_name: The name of the session when assuming the IAM role.
        - mfa: A boolean indicating whether MFA is enabled.
        - profile: The name of the AWS CLI profile to use.
        - aws_access_key_id: The AWS access key ID.
        - aws_secret_access_key: The AWS secret access key.
        - aws_session_token: The AWS session token, optional.
        - retries_max_attempts: The maximum number of retries for the AWS client.
        - regions: A set of regions to audit.
        """
        if aws_session:
            self._session = aws_session
        else:
            aws_setup_session = AwsSetUpSession(
                role_arn=role_arn,
                session_duration=session_duration,
                external_id=external_id,
                role_session_name=role_session_name,
                mfa=mfa,
                profile=profile,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                aws_session_token=aws_session_token,
                retries_max_attempts=retries_max_attempts,
                regions=regions,
            )
            self._session = aws_setup_session._session.current_session
        self._aws_account_id = aws_account_id
        if not aws_partition:
            aws_partition = AwsProvider.validate_credentials(
                self._session, AWS_STS_GLOBAL_ENDPOINT_REGION
            ).arn.partition
        self._aws_partition = aws_partition

        self._enabled_regions = None
        self._findings_per_region = {}

        if aws_security_hub_available_regions:
            self._enabled_regions = self.verify_enabled_per_region(
                aws_security_hub_available_regions,
                self._session,
                aws_account_id,
                aws_partition,
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
            send_only_fails (bool): Flag indicating whether to send only findings with status 'FAIL'.

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

    @staticmethod
    def _check_region_security_hub(
        region: str,
        session: Session,
        aws_account_id: str,
        aws_partition: str,
    ) -> tuple[str, Union[Session, None]]:
        """
        Check if Security Hub is enabled in a specific region and if Prowler integration is active.

        Args:
            region (str): AWS region to check.
            session (Session): AWS session object.
            aws_account_id (str): AWS account ID.
            aws_partition (str): AWS partition.

        Returns:
            tuple: (region, client or None) - Returns client if enabled, None otherwise.
        """
        try:
            logger.info(
                f"Checking if the {SECURITY_HUB_INTEGRATION_NAME} is enabled in the {region} region."
            )
            # Check if security hub is enabled in current region
            security_hub_client = session.client("securityhub", region_name=region)
            security_hub_client.describe_hub()

            # Check if Prowler integration is enabled in Security Hub
            security_hub_prowler_integration_arn = f"arn:{aws_partition}:securityhub:{region}:{aws_account_id}:product-subscription/{SECURITY_HUB_INTEGRATION_NAME}"
            if security_hub_prowler_integration_arn not in str(
                security_hub_client.list_enabled_products_for_import()
            ):
                logger.warning(
                    f"Security Hub is enabled in {region} but Prowler integration does not accept findings. More info: https://docs.prowler.cloud/en/latest/tutorials/aws/securityhub/"
                )
                return region, None
            else:
                return region, session.client("securityhub", region_name=region)

        # Handle all the permissions / configuration errors
        except ClientError as client_error:
            # Check if Account is subscribed to Security Hub
            error_code = client_error.response["Error"]["Code"]
            error_message = client_error.response["Error"]["Message"]
            if (
                error_code == "InvalidAccessException"
                and f"Account {aws_account_id} is not subscribed to AWS Security Hub"
                in error_message
            ):
                logger.warning(
                    f"{client_error.__class__.__name__} -- [{client_error.__traceback__.tb_lineno}]: {client_error}"
                )
            else:
                logger.error(
                    f"{client_error.__class__.__name__} -- [{client_error.__traceback__.tb_lineno}]: {client_error}"
                )
            return region, None
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__} -- [{error.__traceback__.tb_lineno}]: {error}"
            )
            return region, None

    @staticmethod
    def verify_enabled_per_region(
        aws_security_hub_available_regions: list[str],
        session: Session,
        aws_account_id: str,
        aws_partition: str,
    ) -> dict[str, Session]:
        """
        Filters the given list of regions where AWS Security Hub is enabled and returns a dictionary containing the region and their boto3 client if the region and the Prowler integration is enabled.

        Args:
            aws_security_hub_available_regions (list[str]): List of AWS regions to check for Security Hub integration.

        Returns:
            dict: A dictionary containing enabled regions with SecurityHub clients.
        """
        enabled_regions = {}

        # Use ThreadPoolExecutor to check regions in parallel
        with ThreadPoolExecutor(
            max_workers=min(len(aws_security_hub_available_regions), 20)
        ) as executor:
            # Submit all region checks
            future_to_region = {
                executor.submit(
                    SecurityHub._check_region_security_hub,
                    region,
                    session,
                    aws_account_id,
                    aws_partition,
                ): region
                for region in aws_security_hub_available_regions
            }

            # Collect results as they complete
            for future in as_completed(future_to_region):
                try:
                    region, client = future.result()
                    if client is not None:
                        enabled_regions[region] = client
                except Exception as error:
                    logger.error(
                        f"Error checking region {future_to_region[future]}: {error.__class__.__name__} -- [{error.__traceback__.tb_lineno}]: {error}"
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

    @staticmethod
    def test_connection(
        aws_account_id: str,
        aws_partition: str = None,
        regions: set = None,
        raise_on_exception: bool = True,
        profile: str = None,
        aws_region: str = AWS_STS_GLOBAL_ENDPOINT_REGION,
        role_arn: str = None,
        role_session_name: str = ROLE_SESSION_NAME,
        session_duration: int = 3600,
        external_id: str = None,
        mfa_enabled: bool = False,
        aws_access_key_id: str = None,
        aws_secret_access_key: str = None,
        aws_session_token: Optional[str] = None,
    ) -> SecurityHubConnection:
        """
        Test the connection to AWS Security Hub by checking if Security Hub is enabled in the provided region
        and if the Prowler integration is active.

        Args:
            aws_account_id (str): AWS account ID to check for Prowler integration.
            aws_partition (str): AWS partition (e.g., aws, aws-cn, aws-us-gov).
            regions (set): Set of regions to check for Security Hub integration.
            raise_on_exception (bool): Whether to raise an exception if an error occurs.
            profile (str): AWS profile name to use for authentication.
            aws_region (str): AWS region to use for the session.
            role_arn (str): ARN of the IAM role to assume.
            role_session_name (str): Name for the role session.
            session_duration (int): Duration of the role session in seconds.
            external_id (str): External ID to use when assuming the role.
            mfa_enabled (bool): Whether MFA is enabled.
            aws_access_key_id (str): AWS access key ID.
            aws_secret_access_key (str): AWS secret access key.
            aws_session_token (str): AWS session token.

        Returns:
            SecurityHubConnection: An object that contains the result of the test connection operation.
                - is_connected (bool): Indicates whether the connection was successful.
                - error (Exception): An exception object if an error occurs during the connection test.
                - enabled_regions (set): Set of regions where Security Hub is enabled.
                - disabled_regions (set): Set of regions where Security Hub is disabled.
        """
        try:
            disabled_regions = set()
            enabled_regions = set()

            # Set up AWS session
            session = AwsProvider.setup_session(
                mfa=mfa_enabled,
                profile=profile,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                aws_session_token=aws_session_token,
            )
            if not aws_partition:
                aws_partition = AwsProvider.validate_credentials(
                    session, aws_region
                ).arn.partition

            # Handle role assumption if role_arn is provided
            if role_arn:
                session_duration = validate_session_duration(session_duration)
                role_session_name = validate_role_session_name(
                    role_session_name or ROLE_SESSION_NAME
                )
                role_arn = parse_iam_credentials_arn(role_arn)
                assumed_role_information = AWSAssumeRoleInfo(
                    role_arn=role_arn,
                    session_duration=session_duration,
                    external_id=external_id,
                    mfa_enabled=mfa_enabled,
                    role_session_name=role_session_name,
                )
                assumed_role_credentials = AwsProvider.assume_role(
                    session,
                    assumed_role_information,
                )
                session = Session(
                    aws_access_key_id=assumed_role_credentials.aws_access_key_id,
                    aws_secret_access_key=assumed_role_credentials.aws_secret_access_key,
                    aws_session_token=assumed_role_credentials.aws_session_token,
                    region_name=aws_region,
                    profile_name=profile,
                )

            all_regions = AwsProvider.get_available_aws_service_regions(
                service="securityhub", partition=aws_partition
            )

            enabled_regions = SecurityHub.verify_enabled_per_region(
                aws_security_hub_available_regions=all_regions,
                session=session,
                aws_account_id=aws_account_id,
                aws_partition=aws_partition,
            ).keys()
            disabled_regions = all_regions - enabled_regions
            if regions:
                if not any(region in enabled_regions for region in regions):
                    logger.warning(
                        f"Prowler integration is not enabled in regions: {regions - enabled_regions}."
                    )
                    invalid_region_error = SecurityHubInvalidRegionError(
                        message="Given regions have not Security Hub enabled."
                    )
                    if raise_on_exception:
                        raise invalid_region_error
                    return SecurityHubConnection(
                        is_connected=False,
                        error=invalid_region_error,
                        enabled_regions=enabled_regions,
                        disabled_regions=disabled_regions,
                    )
                else:
                    logger.info(
                        f"Prowler integration is enabled in regions: {', '.join(regions)}."
                    )
                    return SecurityHubConnection(
                        is_connected=True,
                        error=None,
                        enabled_regions=enabled_regions,
                        disabled_regions=disabled_regions,
                        partition=aws_partition,
                    )

            if len(enabled_regions) == 0:
                error_str = (
                    "No regions found with the Security Hub integration enabled."
                )
                logger.warning(error_str)
                no_enabled_regions_error = SecurityHubNoEnabledRegionsError(
                    message=error_str
                )
                if raise_on_exception:
                    raise no_enabled_regions_error
                return SecurityHubConnection(
                    is_connected=False,
                    error=no_enabled_regions_error,
                    enabled_regions=enabled_regions,
                    disabled_regions=disabled_regions,
                )
            else:
                logger.info(
                    f"Security Hub is enabled in the following regions: {', '.join(enabled_regions)}."
                )
                return SecurityHubConnection(
                    is_connected=True,
                    error=None,
                    enabled_regions=enabled_regions,
                    disabled_regions=disabled_regions,
                    partition=aws_partition,
                )

        except AWSSetUpSessionError as setup_session_error:
            logger.error(
                f"{setup_session_error.__class__.__name__}[{setup_session_error.__traceback__.tb_lineno}]: {setup_session_error}"
            )
            if raise_on_exception:
                raise setup_session_error
            return SecurityHubConnection(
                is_connected=False,
                error=setup_session_error,
                enabled_regions=set(),
                disabled_regions=set(),
            )

        except AWSArgumentTypeValidationError as validation_error:
            logger.error(
                f"{validation_error.__class__.__name__}[{validation_error.__traceback__.tb_lineno}]: {validation_error}"
            )
            if raise_on_exception:
                raise validation_error
            return SecurityHubConnection(
                is_connected=False,
                error=validation_error,
                enabled_regions=set(),
                disabled_regions=set(),
            )

        except AWSIAMRoleARNRegionNotEmtpyError as arn_region_not_empty_error:
            logger.error(
                f"{arn_region_not_empty_error.__class__.__name__}[{arn_region_not_empty_error.__traceback__.tb_lineno}]: {arn_region_not_empty_error}"
            )
            if raise_on_exception:
                raise arn_region_not_empty_error
            return SecurityHubConnection(
                is_connected=False,
                error=arn_region_not_empty_error,
                enabled_regions=set(),
                disabled_regions=set(),
            )

        except AWSIAMRoleARNPartitionEmptyError as arn_partition_empty_error:
            logger.error(
                f"{arn_partition_empty_error.__class__.__name__}[{arn_partition_empty_error.__traceback__.tb_lineno}]: {arn_partition_empty_error}"
            )
            if raise_on_exception:
                raise arn_partition_empty_error
            return SecurityHubConnection(
                is_connected=False,
                error=arn_partition_empty_error,
                enabled_regions=set(),
                disabled_regions=set(),
            )

        except AWSIAMRoleARNServiceNotIAMnorSTSError as arn_service_not_iam_sts_error:
            logger.error(
                f"{arn_service_not_iam_sts_error.__class__.__name__}[{arn_service_not_iam_sts_error.__traceback__.tb_lineno}]: {arn_service_not_iam_sts_error}"
            )
            if raise_on_exception:
                raise arn_service_not_iam_sts_error
            return SecurityHubConnection(
                is_connected=False,
                error=arn_service_not_iam_sts_error,
                enabled_regions=set(),
                disabled_regions=set(),
            )

        except AWSIAMRoleARNInvalidAccountIDError as arn_invalid_account_id_error:
            logger.error(
                f"{arn_invalid_account_id_error.__class__.__name__}[{arn_invalid_account_id_error.__traceback__.tb_lineno}]: {arn_invalid_account_id_error}"
            )
            if raise_on_exception:
                raise arn_invalid_account_id_error
            return SecurityHubConnection(
                is_connected=False,
                error=arn_invalid_account_id_error,
                enabled_regions=set(),
                disabled_regions=set(),
            )

        except AWSIAMRoleARNInvalidResourceTypeError as arn_invalid_resource_type_error:
            logger.error(
                f"{arn_invalid_resource_type_error.__class__.__name__}[{arn_invalid_resource_type_error.__traceback__.tb_lineno}]: {arn_invalid_resource_type_error}"
            )
            if raise_on_exception:
                raise arn_invalid_resource_type_error
            return SecurityHubConnection(
                is_connected=False,
                error=arn_invalid_resource_type_error,
                enabled_regions=set(),
                disabled_regions=set(),
            )

        except AWSIAMRoleARNEmptyResourceError as arn_empty_resource_error:
            logger.error(
                f"{arn_empty_resource_error.__class__.__name__}[{arn_empty_resource_error.__traceback__.tb_lineno}]: {arn_empty_resource_error}"
            )
            if raise_on_exception:
                raise arn_empty_resource_error
            return SecurityHubConnection(
                is_connected=False,
                error=arn_empty_resource_error,
                enabled_regions=set(),
                disabled_regions=set(),
            )

        except AWSAssumeRoleError as assume_role_error:
            logger.error(
                f"{assume_role_error.__class__.__name__}[{assume_role_error.__traceback__.tb_lineno}]: {assume_role_error}"
            )
            if raise_on_exception:
                raise assume_role_error
            return SecurityHubConnection(
                is_connected=False,
                error=assume_role_error,
                enabled_regions=set(),
                disabled_regions=set(),
            )

        except ProfileNotFound as profile_not_found_error:
            logger.error(
                f"AWSProfileNotFoundError[{profile_not_found_error.__traceback__.tb_lineno}]: {profile_not_found_error}"
            )
            if raise_on_exception:
                raise AWSProfileNotFoundError(
                    file=os.path.basename(__file__),
                    original_exception=profile_not_found_error,
                ) from profile_not_found_error
            return SecurityHubConnection(
                is_connected=False,
                error=profile_not_found_error,
                enabled_regions=set(),
                disabled_regions=set(),
            )

        except NoCredentialsError as no_credentials_error:
            logger.error(
                f"AWSNoCredentialsError[{no_credentials_error.__traceback__.tb_lineno}]: {no_credentials_error}"
            )
            if raise_on_exception:
                raise AWSNoCredentialsError(
                    file=os.path.basename(__file__),
                    original_exception=no_credentials_error,
                ) from no_credentials_error
            return SecurityHubConnection(
                is_connected=False,
                error=no_credentials_error,
                enabled_regions=set(),
                disabled_regions=set(),
            )

        except AWSAccessKeyIDInvalidError as access_key_id_invalid_error:
            logger.error(
                f"{access_key_id_invalid_error.__class__.__name__}[{access_key_id_invalid_error.__traceback__.tb_lineno}]: {access_key_id_invalid_error}"
            )
            if raise_on_exception:
                raise access_key_id_invalid_error
            return SecurityHubConnection(
                is_connected=False,
                error=access_key_id_invalid_error,
                enabled_regions=set(),
                disabled_regions=set(),
            )

        except AWSSecretAccessKeyInvalidError as secret_access_key_invalid_error:
            logger.error(
                f"{secret_access_key_invalid_error.__class__.__name__}[{secret_access_key_invalid_error.__traceback__.tb_lineno}]: {secret_access_key_invalid_error}"
            )
            if raise_on_exception:
                raise secret_access_key_invalid_error
            return SecurityHubConnection(
                is_connected=False,
                error=secret_access_key_invalid_error,
                enabled_regions=set(),
                disabled_regions=set(),
            )

        except AWSSessionTokenExpiredError as session_token_expired:
            logger.error(
                f"{session_token_expired.__class__.__name__}[{session_token_expired.__traceback__.tb_lineno}]: {session_token_expired}"
            )
            if raise_on_exception:
                raise session_token_expired
            return SecurityHubConnection(
                is_connected=False,
                error=session_token_expired,
                enabled_regions=set(),
                disabled_regions=set(),
            )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                raise error
            return SecurityHubConnection(
                is_connected=False,
                error=error,
                enabled_regions=set(),
                disabled_regions=set(),
            )
