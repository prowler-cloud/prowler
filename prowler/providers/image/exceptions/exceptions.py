from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 11000 to 11999 are reserved for Image exceptions
class ImageBaseException(ProwlerException):
    """Base class for Image provider errors."""

    IMAGE_ERROR_CODES = {
        (11000, "ImageNoImagesProvidedError"): {
            "message": "No container images provided for scanning.",
            "remediation": "Provide at least one image using --image or --image-list-file.",
        },
        (11001, "ImageListFileNotFoundError"): {
            "message": "Image list file not found.",
            "remediation": "Ensure the image list file exists at the specified path.",
        },
        (11002, "ImageListFileReadError"): {
            "message": "Error reading image list file.",
            "remediation": "Check file permissions and format. The file should contain one image per line.",
        },
        (11003, "ImageFindingProcessingError"): {
            "message": "Error processing image scan finding.",
            "remediation": "Check the Trivy output format and ensure the finding structure is valid.",
        },
        (11004, "ImageTrivyBinaryNotFoundError"): {
            "message": "Trivy binary not found.",
            "remediation": "Install Trivy from https://trivy.dev/latest/getting-started/installation/",
        },
        (11005, "ImageScanError"): {
            "message": "Error scanning container image.",
            "remediation": "Check the image name and ensure it is accessible.",
        },
        (11006, "ImageInvalidTimeoutError"): {
            "message": "Invalid timeout format.",
            "remediation": "Use a valid timeout like '5m', '300s', or '1h'.",
        },
        (11007, "ImageInvalidScannerError"): {
            "message": "Invalid scanner type.",
            "remediation": "Use valid scanners: vuln, secret, misconfig, license.",
        },
        (11008, "ImageInvalidSeverityError"): {
            "message": "Invalid severity level.",
            "remediation": "Use valid severities: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN.",
        },
        (11009, "ImageInvalidNameError"): {
            "message": "Invalid container image name.",
            "remediation": "Use a valid image reference (e.g., 'alpine:3.18', 'registry.example.com/repo/image:tag').",
        },
        (11010, "ImageInvalidConfigScannerError"): {
            "message": "Invalid image config scanner type.",
            "remediation": "Use valid image config scanners: misconfig, secret.",
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
            11000, file=file, original_exception=original_exception, message=message
        )


class ImageListFileNotFoundError(ImageBaseException):
    """Exception raised when the image list file is not found."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            11001, file=file, original_exception=original_exception, message=message
        )


class ImageListFileReadError(ImageBaseException):
    """Exception raised when the image list file cannot be read."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            11002, file=file, original_exception=original_exception, message=message
        )


class ImageFindingProcessingError(ImageBaseException):
    """Exception raised when a finding cannot be processed."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            11003, file=file, original_exception=original_exception, message=message
        )


class ImageTrivyBinaryNotFoundError(ImageBaseException):
    """Exception raised when the Trivy binary is not found."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            11004, file=file, original_exception=original_exception, message=message
        )


class ImageScanError(ImageBaseException):
    """Exception raised when a general scan error occurs."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            11005, file=file, original_exception=original_exception, message=message
        )


class ImageInvalidTimeoutError(ImageBaseException):
    """Exception raised when an invalid timeout format is provided."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            11006, file=file, original_exception=original_exception, message=message
        )


class ImageInvalidScannerError(ImageBaseException):
    """Exception raised when an invalid scanner type is provided."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            11007, file=file, original_exception=original_exception, message=message
        )


class ImageInvalidSeverityError(ImageBaseException):
    """Exception raised when an invalid severity level is provided."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            11008, file=file, original_exception=original_exception, message=message
        )


class ImageInvalidNameError(ImageBaseException):
    """Exception raised when an invalid container image name is provided."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            11009, file=file, original_exception=original_exception, message=message
        )


class ImageInvalidConfigScannerError(ImageBaseException):
    """Exception raised when an invalid image config scanner type is provided."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            11010, file=file, original_exception=original_exception, message=message
        )
