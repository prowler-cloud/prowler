from typing import Optional

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import (
    AwsProvider,
    get_aws_region_for_sts,
    parse_iam_credentials_arn,
)
from prowler.providers.aws.models import (
    AWSAssumeRoleConfiguration,
    AWSAssumeRoleInfo,
    AWSIdentityInfo,
    AWSSession,
)


class AwsSetUpSession:
    """
    A class to set up the AWS session.

    Attributes:
    - _session: An instance of the AWSSession class.

    Methods:
    - __init__: The constructor for the AwsSetUpSession class.
    """

    _session: AWSSession
    _identity: AWSIdentityInfo

    def __init__(
        self,
        role_arn: str = None,
        session_duration: int = None,
        external_id: str = None,
        role_session_name: str = None,
        mfa: bool = None,
        profile: str = None,
        aws_access_key_id: str = None,
        aws_secret_access_key: str = None,
        aws_session_token: Optional[str] = None,
        retries_max_attempts: int = 3,
        regions: set = set(),
    ) -> None:
        """
        The constructor for the AwsSetUpSession class.

        Parameters:
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

        Returns:

        An instance of the AwsSetUpSession class.
        """

        validate_arguments(
            role_arn=role_arn,
            session_duration=session_duration,
            external_id=external_id,
            role_session_name=role_session_name,
            profile=profile,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
        )
        # Setup the AWS session
        aws_session = AwsProvider.setup_session(
            mfa=mfa,
            profile=profile,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
        )
        session_config = AwsProvider.set_session_config(retries_max_attempts)
        self._session = AWSSession(
            current_session=aws_session,
            session_config=session_config,
            original_session=aws_session,
        )

        ######## Validate AWS credentials
        # After the session is created, validate it
        logger.info("Validating credentials ...")
        sts_region = get_aws_region_for_sts(
            self._session.current_session.region_name, regions
        )

        # Validate the credentials
        caller_identity = AwsProvider.validate_credentials(
            session=self._session.current_session,
            aws_region=sts_region,
        )

        logger.info("Credentials validated")
        ########

        ######## AWS Provider Identity
        # Get profile region
        profile_region = AwsProvider.get_profile_region(self._session.current_session)

        # Set identity
        self._identity = AwsProvider.set_identity(
            caller_identity=caller_identity,
            profile=profile,
            regions=regions,
            profile_region=profile_region,
        )
        ########

        ######## AWS Session with Assume Role (if needed)
        if role_arn:
            # Validate the input role
            valid_role_arn = parse_iam_credentials_arn(role_arn)
            # Set assume IAM Role information
            assumed_role_information = AWSAssumeRoleInfo(
                role_arn=valid_role_arn,
                session_duration=session_duration,
                external_id=external_id,
                mfa_enabled=mfa,
                role_session_name=role_session_name,
                sts_region=sts_region,
            )
            # Assume the IAM Role
            logger.info(f"Assuming role: {assumed_role_information.role_arn.arn}")
            assumed_role_credentials = self.assume_role(
                self._session.current_session,
                assumed_role_information,
            )
            logger.info(f"IAM Role assumed: {assumed_role_information.role_arn.arn}")

            assumed_role_configuration = AWSAssumeRoleConfiguration(
                info=assumed_role_information, credentials=assumed_role_credentials
            )
            # Store the assumed role configuration since it'll be needed to refresh the credentials
            self._assumed_role_configuration = assumed_role_configuration

            # Store a new current session using the assumed IAM Role
            self._session.current_session = self.setup_assumed_session(
                assumed_role_configuration.credentials
            )
            logger.info("Audit session is the new session created assuming an IAM Role")

            # Modify identity for the IAM Role assumed since this will be the identity to audit with
            logger.info("Setting new identity for the AWS IAM Role assumed")
            self._identity.account = assumed_role_configuration.info.role_arn.account_id
            self._identity.partition = (
                assumed_role_configuration.info.role_arn.partition
            )
            self._identity.account_arn = f"arn:{assumed_role_configuration.info.role_arn.partition}:iam::{assumed_role_configuration.info.role_arn.account_id}:root"
        ########


def validate_arguments(
    role_arn: str = None,
    session_duration: int = None,
    external_id: str = None,
    role_session_name: str = None,
    profile: str = None,
    aws_access_key_id: str = None,
    aws_secret_access_key: str = None,
) -> None:
    """
    Validate the arguments provided to the S3 class."

    Parameters:
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

    if role_arn:
        if not session_duration or not external_id or not role_session_name:
            raise ValueError(
                "If a role ARN is provided, a session duration, an external ID, and a role session name are required."
            )
    else:
        if session_duration or external_id or role_session_name:
            raise ValueError(
                "If a session duration, an external ID, or a role session name is provided, a role ARN is required."
            )
        if not profile and not aws_access_key_id and not aws_secret_access_key:
            raise ValueError(
                "If no role ARN is provided, a profile, an AWS access key ID, or an AWS secret access key is required."
            )
