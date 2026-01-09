import os
from typing import Optional

from boto3.session import Session
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

from prowler.lib.logger import logger
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
from prowler.providers.aws.lib.session.aws_set_up_session import (
    AwsSetUpSession,
    parse_iam_credentials_arn,
)
from prowler.providers.aws.lib.sns.exceptions.exceptions import (
    SNSAccessDeniedError,
    SNSClientError,
    SNSInvalidTopicARNError,
    SNSTestConnectionError,
    SNSTopicNotFoundError,
)
from prowler.providers.aws.models import AWSAssumeRoleInfo, AWSSession
from prowler.providers.common.models import Connection


class SNS:
    """
    A class representing Amazon SNS integration for sending security findings as email alerts.

    Attributes:
        _session: An SNS client session for interacting with AWS SNS.
        _topic_arn: The ARN of the SNS topic to publish messages to.

    Methods:
        __init__: Initializes a new instance of the SNS class.
        send_finding: Sends a security finding as a formatted message to the SNS topic.
        test_connection: Tests the connection to the SNS topic.
    """

    _session: Session
    _topic_arn: str

    def __init__(
        self,
        topic_arn: str,
        session: AWSSession = None,
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
    ) -> None:
        """
        Initializes a new instance of the SNS class.

        Args:
            topic_arn: The ARN of the SNS topic to publish messages to.
            session: An instance of the AWSSession class representing the AWS session.
            role_arn: The ARN of the IAM role to assume.
            session_duration: The duration of the session in seconds, between 900 and 43200.
            external_id: The external ID to use when assuming the IAM role.
            role_session_name: The name of the session when assuming the IAM role.
            mfa: A boolean indicating whether MFA is enabled.
            profile: The name of the AWS CLI profile to use.
            aws_access_key_id: The AWS access key ID.
            aws_secret_access_key: The AWS secret access key.
            aws_session_token: The AWS session token, optional.
            retries_max_attempts: The maximum number of retries for the AWS client.
            regions: A set of regions to audit.
        """
        if session:
            self._session = session.client(__class__.__name__.lower())
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
            self._session = aws_setup_session._session.current_session.client(
                __class__.__name__.lower(),
                config=aws_setup_session._session.session_config,
            )

        self._topic_arn = topic_arn

    def send_finding(self, finding_data: dict) -> dict:
        """
        Sends a security finding as a formatted message to the SNS topic.

        Args:
            finding_data: A dictionary containing the finding information including:
                - severity: The severity level of the finding
                - status: The status of the finding
                - check_id: The check identifier
                - check_title: The title of the check
                - resource_name: The name of the resource
                - resource_type: The type of the resource
                - resource_uid: The unique identifier of the resource
                - region: The AWS region
                - account_id: The AWS account ID
                - service: The AWS service name
                - provider: The provider name
                - risk: The risk description
                - remediation_recommendation_text: Remediation recommendations
                - remediation_recommendation_url: URL for remediation documentation
                - remediation_code_cli: CLI commands for remediation
                - remediation_code_terraform: Terraform code for remediation
                - remediation_code_other: Other remediation code
                - resource_tags: Tags associated with the resource
                - compliance: Compliance frameworks
                - prowler_url: URL to the finding in Prowler

        Returns:
            dict: A dictionary containing:
                - success (bool): Whether the message was published successfully
                - message_id (str): The SNS message ID if successful
                - error (str): Error message if failed
        """
        try:
            subject = self._build_subject(finding_data)
            message = self._build_message(finding_data)

            logger.info(
                f"Sending finding {finding_data.get('check_id', 'unknown')} to SNS topic {self._topic_arn}"
            )

            response = self._session.publish(
                TopicArn=self._topic_arn,
                Subject=subject,
                Message=message,
            )

            return {
                "success": True,
                "message_id": response.get("MessageId"),
                "error": None,
            }

        except ClientError as error:
            error_code = error.response.get("Error", {}).get("Code", "")
            error_message = error.response.get("Error", {}).get("Message", "")

            logger.error(
                f"Failed to publish to SNS topic {self._topic_arn}: {error_code} - {error_message}"
            )

            return {
                "success": False,
                "message_id": None,
                "error": f"{error_code}: {error_message}",
            }

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            return {
                "success": False,
                "message_id": None,
                "error": str(error),
            }

    def _build_subject(self, finding_data: dict) -> str:
        """
        Builds the email subject line for the finding.

        Args:
            finding_data: The finding information

        Returns:
            str: The formatted subject line
        """
        severity = finding_data.get("severity", "UNKNOWN")
        check_id = finding_data.get("check_id", "unknown")
        resource_name = finding_data.get("resource_name", "unknown")

        return f"[Prowler Alert] {severity} - {check_id} - {resource_name}"

    def _build_message(self, finding_data: dict) -> str:
        """
        Builds the email message body for the finding.

        Args:
            finding_data: The finding information

        Returns:
            str: The formatted message body
        """
        lines = []
        lines.append("=" * 80)
        lines.append("PROWLER SECURITY FINDING ALERT")
        lines.append("=" * 80)
        lines.append("")

        # Finding Details
        lines.append("FINDING DETAILS:")
        lines.append("-" * 80)
        lines.append(f"Severity:      {finding_data.get('severity', 'N/A')}")
        lines.append(f"Status:        {finding_data.get('status', 'N/A')}")
        lines.append(f"Check ID:      {finding_data.get('check_id', 'N/A')}")
        lines.append(f"Check Title:   {finding_data.get('check_title', 'N/A')}")
        lines.append("")

        # Resource Information
        lines.append("RESOURCE INFORMATION:")
        lines.append("-" * 80)
        lines.append(f"Resource Name: {finding_data.get('resource_name', 'N/A')}")
        lines.append(f"Resource Type: {finding_data.get('resource_type', 'N/A')}")
        lines.append(f"Resource UID:  {finding_data.get('resource_uid', 'N/A')}")
        lines.append(f"Region:        {finding_data.get('region', 'N/A')}")
        lines.append(f"Account ID:    {finding_data.get('account_id', 'N/A')}")
        lines.append(f"Service:       {finding_data.get('service', 'N/A')}")
        lines.append(f"Provider:      {finding_data.get('provider', 'N/A')}")
        lines.append("")

        # Risk Description
        if finding_data.get("risk"):
            lines.append("RISK DESCRIPTION:")
            lines.append("-" * 80)
            lines.append(finding_data["risk"])
            lines.append("")

        # Remediation
        if finding_data.get("remediation_recommendation_text"):
            lines.append("REMEDIATION RECOMMENDATIONS:")
            lines.append("-" * 80)
            lines.append(finding_data["remediation_recommendation_text"])
            lines.append("")

            if finding_data.get("remediation_recommendation_url"):
                lines.append(
                    f"Documentation: {finding_data['remediation_recommendation_url']}"
                )
                lines.append("")

        # Remediation Code - CLI
        if finding_data.get("remediation_code_cli"):
            lines.append("REMEDIATION - AWS CLI:")
            lines.append("-" * 80)
            lines.append(finding_data["remediation_code_cli"])
            lines.append("")

        # Remediation Code - Terraform
        if finding_data.get("remediation_code_terraform"):
            lines.append("REMEDIATION - TERRAFORM:")
            lines.append("-" * 80)
            lines.append(finding_data["remediation_code_terraform"])
            lines.append("")

        # Remediation Code - Other
        if finding_data.get("remediation_code_other"):
            lines.append("REMEDIATION - OTHER:")
            lines.append("-" * 80)
            lines.append(finding_data["remediation_code_other"])
            lines.append("")

        # Resource Tags
        if finding_data.get("resource_tags"):
            lines.append("RESOURCE TAGS:")
            lines.append("-" * 80)
            tags = finding_data["resource_tags"]
            if isinstance(tags, dict):
                for key, value in tags.items():
                    lines.append(f"  {key}: {value}")
            else:
                lines.append(str(tags))
            lines.append("")

        # Compliance
        if finding_data.get("compliance"):
            lines.append("COMPLIANCE FRAMEWORKS:")
            lines.append("-" * 80)
            compliance = finding_data["compliance"]
            if isinstance(compliance, list):
                for framework in compliance:
                    lines.append(f"  - {framework}")
            else:
                lines.append(str(compliance))
            lines.append("")

        # Link to Prowler
        if finding_data.get("prowler_url"):
            lines.append("VIEW IN PROWLER:")
            lines.append("-" * 80)
            lines.append(finding_data["prowler_url"])
            lines.append("")

        lines.append("=" * 80)
        lines.append("This alert was generated by Prowler - https://prowler.com")
        lines.append("=" * 80)

        return "\n".join(lines)

    @staticmethod
    def test_connection(
        topic_arn: str,
        profile: str = None,
        aws_region: str = AWS_STS_GLOBAL_ENDPOINT_REGION,
        role_arn: str = None,
        role_session_name: str = ROLE_SESSION_NAME,
        session_duration: int = 3600,
        external_id: str = None,
        mfa_enabled: bool = False,
        raise_on_exception: bool = True,
        aws_access_key_id: str = None,
        aws_secret_access_key: str = None,
        aws_session_token: Optional[str] = None,
    ) -> Connection:
        """
        Test the connection to the SNS topic by verifying the topic exists and we have permissions to publish.

        Args:
            topic_arn: The ARN of the SNS topic to test.
            profile: The name of the AWS CLI profile to use.
            aws_region: The AWS region to use for the session.
            role_arn: The ARN of the IAM role to assume.
            role_session_name: The name of the session when assuming the IAM role.
            session_duration: The duration of the session in seconds, between 900 and 43200.
            external_id: The external ID to use when assuming the IAM role.
            mfa_enabled: A boolean indicating whether MFA is enabled.
            raise_on_exception: A boolean indicating whether to raise an exception if the connection test fails.
            aws_access_key_id: The AWS access key ID.
            aws_secret_access_key: The AWS secret access key.
            aws_session_token: The AWS session token, optional.

        Returns:
            Connection: An object indicating the status of the connection test.

        Raises:
            Exception: An exception indicating that the connection test failed.
        """
        try:
            session = AwsProvider.setup_session(
                mfa=mfa_enabled,
                profile=profile,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                aws_session_token=aws_session_token,
            )

            if role_arn:
                session_duration = validate_session_duration(session_duration)
                role_session_name = validate_role_session_name(role_session_name)
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

            # Extract region from topic ARN (arn:aws:sns:region:account-id:topic-name)
            topic_region = aws_region
            if topic_arn and topic_arn.startswith("arn:"):
                arn_parts = topic_arn.split(":")
                if len(arn_parts) >= 6 and arn_parts[2] == "sns":
                    topic_region = arn_parts[3]

            sns_client = session.client("sns", region_name=topic_region)

            # Verify the topic exists by getting its attributes
            sns_client.get_topic_attributes(TopicArn=topic_arn)

            logger.info(f"Successfully connected to SNS topic: {topic_arn}")
            return Connection(is_connected=True)

        except AWSSetUpSessionError as setup_session_error:
            logger.error(
                f"{setup_session_error.__class__.__name__}[{setup_session_error.__traceback__.tb_lineno}]: {setup_session_error}"
            )
            if raise_on_exception:
                raise setup_session_error
            return Connection(error=setup_session_error)

        except AWSArgumentTypeValidationError as validation_error:
            logger.error(
                f"{validation_error.__class__.__name__}[{validation_error.__traceback__.tb_lineno}]: {validation_error}"
            )
            if raise_on_exception:
                raise validation_error
            return Connection(error=validation_error)

        except AWSIAMRoleARNRegionNotEmtpyError as arn_region_not_empty_error:
            logger.error(
                f"{arn_region_not_empty_error.__class__.__name__}[{arn_region_not_empty_error.__traceback__.tb_lineno}]: {arn_region_not_empty_error}"
            )
            if raise_on_exception:
                raise arn_region_not_empty_error
            return Connection(error=arn_region_not_empty_error)

        except AWSIAMRoleARNPartitionEmptyError as arn_partition_empty_error:
            logger.error(
                f"{arn_partition_empty_error.__class__.__name__}[{arn_partition_empty_error.__traceback__.tb_lineno}]: {arn_partition_empty_error}"
            )
            if raise_on_exception:
                raise arn_partition_empty_error
            return Connection(error=arn_partition_empty_error)

        except AWSIAMRoleARNServiceNotIAMnorSTSError as arn_service_not_iam_sts_error:
            logger.error(
                f"{arn_service_not_iam_sts_error.__class__.__name__}[{arn_service_not_iam_sts_error.__traceback__.tb_lineno}]: {arn_service_not_iam_sts_error}"
            )
            if raise_on_exception:
                raise arn_service_not_iam_sts_error
            return Connection(error=arn_service_not_iam_sts_error)

        except AWSIAMRoleARNInvalidAccountIDError as arn_invalid_account_id_error:
            logger.error(
                f"{arn_invalid_account_id_error.__class__.__name__}[{arn_invalid_account_id_error.__traceback__.tb_lineno}]: {arn_invalid_account_id_error}"
            )
            if raise_on_exception:
                raise arn_invalid_account_id_error
            return Connection(error=arn_invalid_account_id_error)

        except AWSIAMRoleARNInvalidResourceTypeError as arn_invalid_resource_type_error:
            logger.error(
                f"{arn_invalid_resource_type_error.__class__.__name__}[{arn_invalid_resource_type_error.__traceback__.tb_lineno}]: {arn_invalid_resource_type_error}"
            )
            if raise_on_exception:
                raise arn_invalid_resource_type_error
            return Connection(error=arn_invalid_resource_type_error)

        except AWSIAMRoleARNEmptyResourceError as arn_empty_resource_error:
            logger.error(
                f"{arn_empty_resource_error.__class__.__name__}[{arn_empty_resource_error.__traceback__.tb_lineno}]: {arn_empty_resource_error}"
            )
            if raise_on_exception:
                raise arn_empty_resource_error
            return Connection(error=arn_empty_resource_error)

        except AWSAssumeRoleError as assume_role_error:
            logger.error(
                f"{assume_role_error.__class__.__name__}[{assume_role_error.__traceback__.tb_lineno}]: {assume_role_error}"
            )
            if raise_on_exception:
                raise assume_role_error
            return Connection(error=assume_role_error)

        except ProfileNotFound as profile_not_found_error:
            logger.error(
                f"AWSProfileNotFoundError[{profile_not_found_error.__traceback__.tb_lineno}]: {profile_not_found_error}"
            )
            if raise_on_exception:
                raise AWSProfileNotFoundError(
                    file=os.path.basename(__file__),
                    original_exception=profile_not_found_error,
                ) from profile_not_found_error
            return Connection(error=profile_not_found_error)

        except NoCredentialsError as no_credentials_error:
            logger.error(
                f"AWSNoCredentialsError[{no_credentials_error.__traceback__.tb_lineno}]: {no_credentials_error}"
            )
            if raise_on_exception:
                raise AWSNoCredentialsError(
                    file=os.path.basename(__file__),
                    original_exception=no_credentials_error,
                ) from no_credentials_error
            return Connection(error=no_credentials_error)

        except AWSAccessKeyIDInvalidError as access_key_id_invalid_error:
            logger.error(
                f"{access_key_id_invalid_error.__class__.__name__}[{access_key_id_invalid_error.__traceback__.tb_lineno}]: {access_key_id_invalid_error}"
            )
            if raise_on_exception:
                raise access_key_id_invalid_error
            return Connection(error=access_key_id_invalid_error)

        except AWSSecretAccessKeyInvalidError as secret_access_key_invalid_error:
            logger.error(
                f"{secret_access_key_invalid_error.__class__.__name__}[{secret_access_key_invalid_error.__traceback__.tb_lineno}]: {secret_access_key_invalid_error}"
            )
            if raise_on_exception:
                raise secret_access_key_invalid_error
            return Connection(error=secret_access_key_invalid_error)

        except AWSSessionTokenExpiredError as session_token_expired:
            logger.error(
                f"{session_token_expired.__class__.__name__}[{session_token_expired.__traceback__.tb_lineno}]: {session_token_expired}"
            )
            if raise_on_exception:
                raise session_token_expired
            return Connection(error=session_token_expired)

        except ClientError as client_error:
            error_code = client_error.response.get("Error", {}).get("Code", "")
            error_message = client_error.response.get("Error", {}).get("Message", "")

            if raise_on_exception:
                if error_code == "NotFound" or "does not exist" in error_message:
                    raise SNSTopicNotFoundError(
                        topic_arn=topic_arn, original_exception=client_error
                    )
                elif error_code == "AuthorizationError" or "AccessDenied" in error_code:
                    raise SNSAccessDeniedError(
                        topic_arn=topic_arn, original_exception=client_error
                    )
                elif "InvalidParameter" in error_code:
                    raise SNSInvalidTopicARNError(
                        topic_arn=topic_arn, original_exception=client_error
                    )
                else:
                    raise SNSClientError(original_exception=client_error)
            return Connection(error=client_error)

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                raise SNSTestConnectionError(original_exception=error)
            return Connection(is_connected=False, error=error)
