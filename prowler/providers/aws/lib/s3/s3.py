import tempfile
from os import path
from tempfile import NamedTemporaryFile
from typing import Optional

from botocore import exceptions

from prowler.lib.logger import logger
from prowler.lib.outputs.output import Output
from prowler.providers.aws.aws_provider import (
    AwsProvider,
    get_aws_region_for_sts,
    parse_iam_credentials_arn,
)
from prowler.providers.aws.lib.s3.exceptions.exceptions import (
    S3BucketAccessDeniedError,
    S3ClientError,
    S3IllegalLocationConstraintError,
    S3InvalidBucketNameError,
    S3TestConnectionError,
)
from prowler.providers.aws.models import (
    AWSAssumeRoleConfiguration,
    AWSAssumeRoleInfo,
    AWSIdentityInfo,
    AWSSession,
)
from prowler.providers.common.models import Connection


class S3:
    """
    A class representing an S3 bucket.

    Attributes:
    - _session: An instance of the `Session` class representing the AWS session.
    - _bucket_name: A string representing the name of the S3 bucket.
    - _output_directory: A string representing the output directory path.

    Methods:
    - __init__: Initializes a new instance of the `S3` class.
    - get_object_path: Returns the object path within the S3 bucket based on the provided output directory.
    - generate_subfolder_name_by_extension: Generates a subfolder name based on the provided file extension.
    - send_to_bucket: Sends the provided outputs to the S3 bucket.
    """

    _session: AWSSession
    _identity: AWSIdentityInfo
    _bucket_name: str
    _output_directory: str

    def __init__(
        self,
        bucket_name: str,
        output_directory: str,
        session: AWSSession = None,
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
        Initializes a new instance of the `S3` class.

        Parameters:
        - session: An instance of the `AWSSession` class representing the AWS session.
        - bucket_name: A string representing the name of the S3 bucket.
        - output_directory: A string representing the output directory path.
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
        if session:
            self._session = session.client(__class__.__name__.lower())
        else:
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
            profile_region = AwsProvider.get_profile_region(
                self._session.current_session
            )

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
                logger.info(
                    f"IAM Role assumed: {assumed_role_information.role_arn.arn}"
                )

                assumed_role_configuration = AWSAssumeRoleConfiguration(
                    info=assumed_role_information, credentials=assumed_role_credentials
                )
                # Store the assumed role configuration since it'll be needed to refresh the credentials
                self._assumed_role_configuration = assumed_role_configuration

                # Store a new current session using the assumed IAM Role
                self._session.current_session = self.setup_assumed_session(
                    assumed_role_configuration.credentials
                )
                logger.info(
                    "Audit session is the new session created assuming an IAM Role"
                )

                # Modify identity for the IAM Role assumed since this will be the identity to audit with
                logger.info("Setting new identity for the AWS IAM Role assumed")
                self._identity.account = (
                    assumed_role_configuration.info.role_arn.account_id
                )
                self._identity.partition = (
                    assumed_role_configuration.info.role_arn.partition
                )
                self._identity.account_arn = f"arn:{assumed_role_configuration.info.role_arn.partition}:iam::{assumed_role_configuration.info.role_arn.account_id}:root"
            ########

        self._bucket_name = bucket_name
        self._output_directory = output_directory

    @staticmethod
    def get_object_path(output_directory: str) -> str:
        """
        Return the object path within the S3 bucket based on the provided output directory.
        If the output directory contains "prowler/", it is removed to ensure the correct path is returned.

        Parameters:
        - output_directory: A string representing the output directory path.

        Returns:
        - A string representing the object path within the S3 bucket.
        """
        bucket_remote_dir = output_directory
        if "prowler/" in bucket_remote_dir:  # Check if it is not a custom directory
            bucket_remote_dir = bucket_remote_dir.partition("prowler/")[-1]

        return bucket_remote_dir

    @staticmethod
    def generate_subfolder_name_by_extension(extension: str) -> str:
        """
        Generate a subfolder name based on the provided file extension.

        Parameters:
        - extension: A string representing the file extension.

        Returns:
        - A string representing the subfolder name based on the extension.
        """
        subfolder_name = ""
        if extension == ".ocsf.json":
            subfolder_name = "json-ocsf"
        elif extension == ".asff.json":
            subfolder_name = "json-asff"
        else:
            subfolder_name = extension.lstrip(".")
        return subfolder_name

    # TODO: Review the logic behind in Microsoft Windows
    def send_to_bucket(
        self, outputs: dict[str, list[Output]]
    ) -> dict[str, dict[str, list[str]]]:
        """
        Send the provided outputs to the S3 bucket.

        Parameters:
        - outputs: A dictionary where keys are strings and values are lists of Output objects.

        Returns:
        - A dictionary containing two keys: "success" and "failure", each holding a dictionary where keys are strings and values are lists of strings representing the uploaded object names or tuples of object names and errors respectively.
        """
        try:
            uploaded_objects = {"success": {}, "failure": {}}
            # Keys are regular and/or compliance
            for key, output_list in outputs.items():
                for output in output_list:
                    try:
                        # Object is not written to file so we need to temporarily write it
                        if not output.file_descriptor:
                            output.file_descriptor = NamedTemporaryFile(mode="a")

                        bucket_directory = self.get_object_path(self._output_directory)
                        basename = path.basename(output.file_descriptor.name)

                        if key == "compliance":
                            object_name = f"{bucket_directory}/{key}/{basename}"
                        else:
                            object_name = f"{bucket_directory}/{self.generate_subfolder_name_by_extension(output.file_extension)}/{basename}"
                        logger.info(
                            f"Sending output file {output.file_descriptor.name} to S3 bucket {self._bucket_name}"
                        )

                        # TODO: This will need further optimization if some processes are calling this since the files are written
                        # into the local filesystem because S3 upload file is the recommended way.
                        # https://aws.amazon.com/blogs/developer/uploading-files-to-amazon-s3/
                        self._session.upload_file(
                            output.file_descriptor.name, self._bucket_name, object_name
                        )

                        if output.file_extension in uploaded_objects["success"]:
                            uploaded_objects["success"][output.file_extension].append(
                                object_name
                            )
                        else:
                            uploaded_objects["success"] = {
                                output.file_extension: [object_name]
                            }
                    except Exception as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        if output.file_extension in uploaded_objects["failure"]:
                            uploaded_objects["failure"][output.file_extension].append(
                                (object_name, error)
                            )
                        else:
                            uploaded_objects["failure"] = {
                                output.file_extension: [(object_name, error)]
                            }

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
        return uploaded_objects

    @staticmethod
    def test_connection(
        session, bucket_name: str, raise_on_exception: bool = True
    ) -> Connection:
        """
        Test the connection to the S3 bucket.

        Parameters:
        - session: An instance of the `Session` class representing the AWS session.
        - bucket_name: A string representing the name of the S3 bucket.
        - raise_on_exception: A boolean indicating whether to raise an exception if the connection test fails.

        Returns:
        - A Connection object indicating the status of the connection test.

        Raises:
        - Exception: An exception indicating that the connection test failed.
        """
        try:
            s3_client = session.client(__class__.__name__.lower())
            if "s3://" in bucket_name:
                bucket_name = bucket_name.removeprefix("s3://")
            # Check for the bucket location
            bucket_location = s3_client.get_bucket_location(Bucket=bucket_name)
            if bucket_location["LocationConstraint"] == "EU":
                bucket_location["LocationConstraint"] = "eu-west-1"
            if (
                bucket_location["LocationConstraint"] == ""
                or bucket_location["LocationConstraint"] is None
            ):
                bucket_location["LocationConstraint"] = "us-east-1"

            # If the bucket location is not the same as the session region, change the session region
            if (
                session.region_name != bucket_location["LocationConstraint"]
                and bucket_location["LocationConstraint"] is not None
            ):
                s3_client = session.client(
                    __class__.__name__.lower(),
                    region_name=bucket_location["LocationConstraint"],
                )
            # Set a Temp file to upload
            with tempfile.TemporaryFile() as temp_file:
                temp_file.write(b"Test Prowler Connection")
                temp_file.seek(0)
                s3_client.upload_fileobj(
                    temp_file, bucket_name, "test-prowler-connection.txt"
                )

            # Try to delete the file
            s3_client.delete_object(
                Bucket=bucket_name, Key="test-prowler-connection.txt"
            )
            return Connection(is_connected=True)

        except exceptions.ClientError as client_error:
            if raise_on_exception:
                if (
                    "specified bucket does not exist"
                    in client_error.response["Error"]["Message"]
                ):
                    raise S3InvalidBucketNameError(original_exception=client_error)
                elif (
                    "IllegalLocationConstraintException"
                    in client_error.response["Error"]["Message"]
                ):
                    raise S3IllegalLocationConstraintError(
                        original_exception=client_error
                    )
                elif "AccessDenied" in client_error.response["Error"]["Code"]:
                    raise S3BucketAccessDeniedError(original_exception=client_error)
                else:
                    raise S3ClientError(original_exception=client_error)
            return Connection(is_connected=False, error=client_error)

        except Exception as error:
            if raise_on_exception:
                raise S3TestConnectionError(original_exception=error)
            return False


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
