from prowler.exceptions.exceptions import ProwlerException


class AWSBaseException(ProwlerException):
    """Base class for AWS errors."""

    AWS_ERROR_CODES = {
        (1902, "AWSClientError"): {
            "message": "AWS ClientError occurred",
            "remediation": "Check your AWS client configuration and permissions.",
        },
        (1903, "AWSProfileNotFoundError"): {
            "message": "AWS Profile not found",
            "remediation": "Ensure the AWS profile is correctly configured, please visit https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-files.html",
        },
        (1904, "AWSNoCredentialsError"): {
            "message": "No AWS credentials found",
            "remediation": "Verify that AWS credentials are properly set up, please visit https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/aws/authentication/ and https://docs.aws.amazon.com/cli/v1/userguide/cli-chap-configure.html",
        },
        (1905, "AWSArgumentTypeValidationError"): {
            "message": "AWS argument type validation error",
            "remediation": "Check the provided argument types specific to AWS and ensure they meet the required format. For session duration check: https://docs.aws.amazon.com/singlesignon/latest/userguide/howtosessionduration.html and for role session name check: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html#iam-term-role-session-name",
        },
        (1906, "AWSSetUpSessionError"): {
            "message": "AWS session setup error",
            "remediation": "Check the AWS session setup and ensure it is properly configured, please visit https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html and check if the provided profile has the necessary permissions.",
        },
        (1907, "AWSIAMRoleARNRegionNotEmtpy"): {
            "message": "AWS IAM Role ARN region is not empty",
            "remediation": "Check the AWS IAM Role ARN region and ensure it is empty, visit https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-arns for more information.",
        },
        (1908, "AWSIAMRoleARNPartitionEmpty"): {
            "message": "AWS IAM Role ARN partition is empty",
            "remediation": "Check the AWS IAM Role ARN partition and ensure it is not empty, visit https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-arns for more information.",
        },
        (1909, "AWSIAMRoleARNMissingFields"): {
            "message": "AWS IAM Role ARN missing fields",
            "remediation": "Check the AWS IAM Role ARN and ensure all required fields are present, visit https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-arns for more information.",
        },
        (1910, "AWSIAMRoleARNServiceNotIAMnorSTS"): {
            "message": "AWS IAM Role ARN service is not IAM nor STS",
            "remediation": "Check the AWS IAM Role ARN service and ensure it is either IAM or STS, visit https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-arns for more information.",
        },
        (1911, "AWSIAMRoleARNInvalidAccountID"): {
            "message": "AWS IAM Role ARN account ID is invalid",
            "remediation": "Check the AWS IAM Role ARN account ID and ensure it is a valid 12-digit number, visit https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-arns for more information.",
        },
        (1912, "AWSIAMRoleARNInvalidResourceType"): {
            "message": "AWS IAM Role ARN resource type is invalid",
            "remediation": "Check the AWS IAM Role ARN resource type and ensure it is valid, resources types are: role, user, assumed-role, root, federated-user, visit https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-arns for more information.",
        },
        (1913, "AWSIAMRoleARNEmptyResource"): {
            "message": "AWS IAM Role ARN resource is empty",
            "remediation": "Check the AWS IAM Role ARN resource and ensure it is not empty, visit https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-arns for more information.",
        },
        (1914, "AWSAssumeRoleError"): {
            "message": "AWS assume role error",
            "remediation": "Check the AWS assume role configuration and ensure it is properly set up, please visit https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/aws/role-assumption/ and https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html#iam-term-role-session-name",
        },
        (1915, "AWSAccessKeyIDInvalid"): {
            "message": "AWS Access Key ID or Session Token is invalid",
            "remediation": "Check your AWS Access Key ID or Session Token and ensure it is valid.",
        },
        (1916, "AWSSecretAccessKeyInvalid"): {
            "message": "AWS Secret Access Key is invalid",
            "remediation": "Check your AWS Secret Access Key and signing method and ensure it is valid.",
        },
        (1917, "AWSInvalidAccountCredentials"): {
            "message": "The provided AWS credentials belong to a different account",
            "remediation": "Check the provided AWS credentials and review if belong to the account you want to use.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        error_info = self.AWS_ERROR_CODES.get((code, self.__class__.__name__))
        if message:
            error_info["message"] = message
        super().__init__(
            code,
            provider="AWS",
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
            1902, file=file, original_exception=original_exception, message=message
        )


class AWSProfileNotFoundError(AWSCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1903, file=file, original_exception=original_exception, message=message
        )


class AWSNoCredentialsError(AWSCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1904, file=file, original_exception=original_exception, message=message
        )


class AWSArgumentTypeValidationError(AWSBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1905, file=file, original_exception=original_exception, message=message
        )


class AWSSetUpSessionError(AWSBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1906, file=file, original_exception=original_exception, message=message
        )


class AWSRoleArnError(AWSBaseException):
    """Base class for AWS role ARN errors."""

    def __init__(self, code, file=None, original_exception=None, message=None):
        super().__init__(code, file, original_exception, message)


class AWSIAMRoleARNRegionNotEmtpy(AWSRoleArnError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1907, file=file, original_exception=original_exception, message=message
        )


class AWSIAMRoleARNPartitionEmpty(AWSRoleArnError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1908, file=file, original_exception=original_exception, message=message
        )


class AWSIAMRoleARNMissingFields(AWSRoleArnError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1909, file=file, original_exception=original_exception, message=message
        )


class AWSIAMRoleARNServiceNotIAMnorSTS(AWSRoleArnError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1910, file=file, original_exception=original_exception, message=message
        )


class AWSIAMRoleARNInvalidAccountID(AWSRoleArnError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1911, file=file, original_exception=original_exception, message=message
        )


class AWSIAMRoleARNInvalidResourceType(AWSRoleArnError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1912, file=file, original_exception=original_exception, message=message
        )


class AWSIAMRoleARNEmptyResource(AWSRoleArnError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1913, file=file, original_exception=original_exception, message=message
        )


class AWSAssumeRoleError(AWSBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1914, file=file, original_exception=original_exception, message=message
        )


class AWSAccessKeyIDInvalid(AWSCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1915, file=file, original_exception=original_exception, message=message
        )


class AWSSecretAccessKeyInvalid(AWSCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1916, file=file, original_exception=original_exception, message=message
        )


class AWSInvalidAccountCredentials(AWSCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1917, file=file, original_exception=original_exception, message=message
        )
