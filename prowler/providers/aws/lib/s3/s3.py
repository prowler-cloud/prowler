import os
import tempfile
from os import path
from tempfile import NamedTemporaryFile
from typing import Optional

from boto3.session import Session
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

from prowler.lib.logger import logger
from prowler.lib.outputs.output import Output
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
from prowler.providers.aws.lib.s3.exceptions.exceptions import (
    S3BucketAccessDeniedError,
    S3ClientError,
    S3IllegalLocationConstraintError,
    S3InvalidBucketNameError,
    S3InvalidBucketRegionError,
    S3TestConnectionError,
)
from prowler.providers.aws.lib.session.aws_set_up_session import (
    AwsSetUpSession,
    parse_iam_credentials_arn,
)
from prowler.providers.aws.models import AWSAssumeRoleInfo, AWSIdentityInfo, AWSSession
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
        Initializes a new instance of the `S3` class.

        Args:
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

        Returns:
        - None
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
            extension_to_content_type = {
                ".html": "text/html",
                ".csv": "text/csv",
                ".ocsf.json": "application/json",
                ".asff.json": "application/json",
            }
            # Keys are regular and/or compliance
            for key, output_list in outputs.items():
                for output in output_list:
                    try:
                        # Object is not written to file so we need to temporarily write it
                        if not output.file_descriptor:
                            output.file_descriptor = NamedTemporaryFile(mode="a")

                        bucket_directory = self.get_object_path(self._output_directory)
                        basename = path.basename(output.file_descriptor.name)
                        file_extension = output.file_extension

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
                            Filename=output.file_descriptor.name,
                            Bucket=self._bucket_name,
                            Key=object_name,
                            ExtraArgs={
                                "ContentType": extension_to_content_type[file_extension]
                            },
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
        bucket_name: str,
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
        # TODO: Refactor this method, the AWSProvider.test_connection() and the SecurityHubProvider.test_connection() are similar.
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
            s3_client = session.client(__class__.__name__.lower())
            if "s3://" in bucket_name:
                bucket_name = bucket_name.removeprefix("s3://")
            # Check bucket location, requires s3:ListBucket permission
            # https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadBucket.html
            bucket_region = s3_client.head_bucket(Bucket=bucket_name).get(
                "BucketRegion"
            )
            if bucket_region is None:
                exception = S3InvalidBucketRegionError()
                if raise_on_exception:
                    raise exception
                return Connection(error=exception)

            # If the bucket location is not the same as the session region, change the session region
            if session.region_name != bucket_region:
                s3_client = session.client(
                    __class__.__name__.lower(),
                    region_name=bucket_region,
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
        except S3InvalidBucketRegionError as invalid_bucket_region_error:
            logger.error(
                f"{invalid_bucket_region_error.__class__.__name__}[{invalid_bucket_region_error.__traceback__.tb_lineno}]: {invalid_bucket_region_error}"
            )
            if raise_on_exception:
                raise invalid_bucket_region_error
            return Connection(error=invalid_bucket_region_error)
        except ClientError as client_error:
            if raise_on_exception:
                if (
                    "specified bucket does not exist"
                    in client_error.response["Error"]["Message"]
                    or "Not Found" in client_error.response["Error"]["Message"]
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
            return Connection(error=client_error)

        except Exception as error:
            if raise_on_exception:
                raise S3TestConnectionError(original_exception=error)
            return Connection(is_connected=False, error=error)
