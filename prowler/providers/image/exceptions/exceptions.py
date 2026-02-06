from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 9000 to 9999 are reserved for Image exceptions
class ImageBaseException(ProwlerException):
    """Base class for Image provider errors."""

    IMAGE_ERROR_CODES = {
        (9000, "ImageNoImagesProvidedError"): {
            "message": "No container images provided for scanning.",
            "remediation": "Provide at least one image using --image or --image-list-file.",
        },
        (9001, "ImageListFileNotFoundError"): {
            "message": "Image list file not found.",
            "remediation": "Ensure the image list file exists at the specified path.",
        },
        (9002, "ImageListFileReadError"): {
            "message": "Error reading image list file.",
            "remediation": "Check file permissions and format. The file should contain one image per line.",
        },
        (9003, "ImageFindingProcessingError"): {
            "message": "Error processing image scan finding.",
            "remediation": "Check the Trivy output format and ensure the finding structure is valid.",
        },
        (9004, "ImageTrivyBinaryNotFoundError"): {
            "message": "Trivy binary not found.",
            "remediation": "Install Trivy from https://trivy.dev/latest/getting-started/installation/",
        },
        (9005, "ImageScanError"): {
            "message": "Error scanning container image.",
            "remediation": "Check the image name and ensure it is accessible.",
        },
        (9006, "ImageDockerLoginError"): {
            "message": "Docker login failed for registry authentication.",
            "remediation": "Check your registry credentials and ensure the registry is reachable.",
        },
        (9007, "ImageDockerNotFoundError"): {
            "message": "Docker binary not found.",
            "remediation": "Install Docker to enable private registry authentication via docker login.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        error_info = self.IMAGE_ERROR_CODES.get((code, self.__class__.__name__))
        if message:
            error_info["message"] = message
        super().__init__(
            code,
            source="Image",
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class ImageNoImagesProvidedError(ImageBaseException):
    """Exception raised when no container images are provided for scanning."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9000, file=file, original_exception=original_exception, message=message
        )


class ImageListFileNotFoundError(ImageBaseException):
    """Exception raised when the image list file is not found."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9001, file=file, original_exception=original_exception, message=message
        )


class ImageListFileReadError(ImageBaseException):
    """Exception raised when the image list file cannot be read."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9002, file=file, original_exception=original_exception, message=message
        )


class ImageFindingProcessingError(ImageBaseException):
    """Exception raised when a finding cannot be processed."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9003, file=file, original_exception=original_exception, message=message
        )


class ImageTrivyBinaryNotFoundError(ImageBaseException):
    """Exception raised when the Trivy binary is not found."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9004, file=file, original_exception=original_exception, message=message
        )


class ImageScanError(ImageBaseException):
    """Exception raised when a general scan error occurs."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9005, file=file, original_exception=original_exception, message=message
        )


class ImageDockerLoginError(ImageBaseException):
    """Exception raised when docker login fails."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9006, file=file, original_exception=original_exception, message=message
        )


class ImageDockerNotFoundError(ImageBaseException):
    """Exception raised when the docker binary is not found."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9007, file=file, original_exception=original_exception, message=message
        )
