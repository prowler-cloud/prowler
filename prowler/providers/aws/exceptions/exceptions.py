from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 1000 to 1999 are reserved for AWS exceptions
class AWSBaseException(ProwlerException):
    """Base class for AWS errors."""

    AWS_ERROR_CODES = {
        (1000, "AWSClientError"): {
            "message": "AWS ClientError occurred",
            "remediation": "Check your AWS client configuration and permissions.",
        },
        (1001, "AWSProfileNotFoundError"): {
            "message": "AWS Profile not found",
            "remediation": "Ensure the AWS profile is correctly configured, please visit https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-files.html",
        },
        (1002, "AWSNoCredentialsError"): {
            "message": "No AWS credentials found",
            "remediation": "Verify that AWS credentials are properly set up, please visit https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/aws/authentication/ and https://docs.aws.amazon.com/cli/v1/userguide/cli-chap-configure.html",
        },
        (1003, "AWSArgumentTypeValidationError"): {
            "message": "AWS argument type validation error",
            "remediation": "Check the provided argument types specific to AWS and ensure they meet the required format. For session duration check: https://docs.aws.amazon.com/singlesignon/latest/userguide/howtosessionduration.html and for role session name check: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html#iam-term-role-session-name",
        },
        (1004, "AWSSetUpSessionError"): {
            "message": "AWS session setup error",
            "remediation": "Check the AWS session setup and ensure it is properly configured, please visit https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html and check if the provided profile has the necessary permissions.",
        },
        (1005, "AWSIAMRoleARNRegionNotEmtpyError"): {
            "message": "AWS IAM Role ARN region is not empty",
            "remediation": "Check the AWS IAM Role ARN region and ensure it is empty, visit https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-arns for more information.",
        },
        (1006, "AWSIAMRoleARNPartitionEmptyError"): {
            "message": "AWS IAM Role ARN partition is empty",
            "remediation": "Check the AWS IAM Role ARN partition and ensure it is not empty, visit https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-arns for more information.",
        },
        (1007, "AWSIAMRoleARNMissingFieldsError"): {
            "message": "AWS IAM Role ARN missing fields",
            "remediation": "Check the AWS IAM Role ARN and ensure all required fields are present, visit https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-arns for more information.",
        },
        (1008, "AWSIAMRoleARNServiceNotIAMnorSTSError"): {
            "message": "AWS IAM Role ARN service is not IAM nor STS",
            "remediation": "Check the AWS IAM Role ARN service and ensure it is either IAM or STS, visit https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-arns for more information.",
        },
        (1009, "AWSIAMRoleARNInvalidAccountIDError"): {
            "message": "AWS IAM Role ARN account ID is invalid",
            "remediation": "Check the AWS IAM Role ARN account ID and ensure it is a valid 12-digit number, visit https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-arns for more information.",
        },
        (1010, "AWSIAMRoleARNInvalidResourceTypeError"): {
            "message": "AWS IAM Role ARN resource type is invalid",
            "remediation": "Check the AWS IAM Role ARN resource type and ensure it is valid, resources types are: role, user, assumed-role, root, federated-user, visit https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-arns for more information.",
        },
        (1011, "AWSIAMRoleARNEmptyResourceError"): {
            "message": "AWS IAM Role ARN resource is empty",
            "remediation": "Check the AWS IAM Role ARN resource and ensure it is not empty, visit https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-arns for more information.",
        },
        (1012, "AWSAssumeRoleError"): {
            "message": "AWS assume role error",
            "remediation": "Check the AWS assume role configuration and ensure it is properly set up, please visit https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/aws/role-assumption/ and https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html#iam-term-role-session-name",
        },
        (1013, "AWSAccessKeyIDInvalidError"): {
            "message": "AWS Access Key ID or Session Token is invalid",
            "remediation": "Check your AWS Access Key ID or Session Token and ensure it is valid.",
        },
        (1014, "AWSSecretAccessKeyInvalidError"): {
            "message": "AWS Secret Access Key is invalid",
            "remediation": "Check your AWS Secret Access Key and signing method and ensure it is valid.",
        },
        (1015, "AWSInvalidProviderIdError"): {
            "message": "The provided AWS credentials belong to a different account",
            "remediation": "Check the provided AWS credentials and review if belong to the account you want to use.",
        },
        (1016, "AWSSessionTokenExpiredError"): {
            "message": "The provided AWS Session Token is expired",
            "remediation": "Get a new AWS Session Token and configure it for the provider.",
        },
        (1917, "AWSInvalidPartitionError"): {
            "message": "The provided AWS partition is invalid",
            "remediation": "Check the provided AWS partition and ensure it is valid.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        error_info = self.AWS_ERROR_CODES.get((code, self.__class__.__name__))
        if message:
            error_info["message"] = message
        super().__init__(
            code,
            source="AWS",
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class AWSCredentialsError(AWSBaseException):
    """Base class for AWS credentials errors."""

    def __init__(self, code, file=None, original_exception=None, message=None):
        super().__init__(code, file, original_exception, message)


class AWSClientError(AWSCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1000, file=file, original_exception=original_exception, message=message
        )


class AWSProfileNotFoundError(AWSCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1001, file=file, original_exception=original_exception, message=message
        )


class AWSNoCredentialsError(AWSCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1002, file=file, original_exception=original_exception, message=message
        )


class AWSArgumentTypeValidationError(AWSBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1003, file=file, original_exception=original_exception, message=message
        )


class AWSSetUpSessionError(AWSBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1004, file=file, original_exception=original_exception, message=message
        )


class AWSRoleArnError(AWSBaseException):
    """Base class for AWS role ARN errors."""

    def __init__(self, code, file=None, original_exception=None, message=None):
        super().__init__(code, file, original_exception, message)


class AWSIAMRoleARNRegionNotEmtpyError(AWSRoleArnError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1005, file=file, original_exception=original_exception, message=message
        )


class AWSIAMRoleARNPartitionEmptyError(AWSRoleArnError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1006, file=file, original_exception=original_exception, message=message
        )


class AWSIAMRoleARNMissingFieldsError(AWSRoleArnError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1007, file=file, original_exception=original_exception, message=message
        )


class AWSIAMRoleARNServiceNotIAMnorSTSError(AWSRoleArnError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1008, file=file, original_exception=original_exception, message=message
        )


class AWSIAMRoleARNInvalidAccountIDError(AWSRoleArnError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1009, file=file, original_exception=original_exception, message=message
        )


class AWSIAMRoleARNInvalidResourceTypeError(AWSRoleArnError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1010, file=file, original_exception=original_exception, message=message
        )


class AWSIAMRoleARNEmptyResourceError(AWSRoleArnError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1011, file=file, original_exception=original_exception, message=message
        )


class AWSAssumeRoleError(AWSBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1012, file=file, original_exception=original_exception, message=message
        )


class AWSAccessKeyIDInvalidError(AWSCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1013, file=file, original_exception=original_exception, message=message
        )


class AWSSecretAccessKeyInvalidError(AWSCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1014, file=file, original_exception=original_exception, message=message
        )


class AWSInvalidProviderIdError(AWSCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1015, file=file, original_exception=original_exception, message=message
        )


class AWSSessionTokenExpiredError(AWSCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1016, file=file, original_exception=original_exception, message=message
        )


class AWSInvalidPartitionError(AWSBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1917, file=file, original_exception=original_exception, message=message
        )
