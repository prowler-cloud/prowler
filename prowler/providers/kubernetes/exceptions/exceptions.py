from prowler.exceptions.exceptions import ProwlerException


class KubernetesBaseException(ProwlerException):
    """Base class for Kubernetes errors."""

    KUBERNETES_ERROR_CODES = {
        (1925, "KubernetesCloudResourceManagerAPINotUsedError"): {
            "message": "Cloud Resource Manager API is not enabled, blocking access to necessary resources.",
            "remediation": "Refer to the Kubernetes documentation to enable the Cloud Resource Manager API: https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
        },
        (1926, "KubernetesSetUpSessionError"): {
            "message": "Failed to establish a Kubernetes session, preventing further actions.",
            "remediation": "Verify your session setup, including credentials and Kubernetes cluster configuration. Refer to this guide for proper setup: https://kubernetes.io/docs/tasks/access-application-cluster/configure-access-multiple-clusters/",
        },
        (1930, "KubernetesAPIError"): {
            "message": "An error occurred while interacting with the Kubernetes API.",
            "remediation": "Check the API request and ensure it is properly formatted. Refer to the Kubernetes API documentation for guidance: https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.22/",
        },
        (1931, "KubernetesTimeoutError"): {
            "message": "The request to the Kubernetes API timed out.",
            "remediation": "Check the network connection and the Kubernetes API server status. For information on troubleshooting timeouts, refer to the Kubernetes documentation: https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.22/#-strong-timeout-strong-",
        },
        (1934, "KubernetesError"): {
            "message": "An error occurred in the Kubernetes provider.",
            "remediation": "Check the provider code and configuration to identify the issue. For more information on troubleshooting Kubernetes providers, refer to the Kubernetes documentation: https://kubernetes.io/docs/reference/",
        },
    }

    def __init__(
        self,
        code,
        file=None,
        original_exception=None,
        message=None,
    ):
        provider = "Kubernetes"
        error_info = self.KUBERNETES_ERROR_CODES.get((code, self.__class__.__name__))
        if message:
            error_info["message"] = message
        super().__init__(
            code=code,
            provider=provider,
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class KubernetesError(KubernetesBaseException):
    def __init__(self, code, file=None, original_exception=None, message=None):
        super().__init__(code, file, original_exception, message)


class KubernetesCloudResourceManagerAPINotUsedError(KubernetesBaseException):
    def __init__(self, code, file=None, original_exception=None, message=None):
        super().__init__(code, file, original_exception, message)


class KubernetesSetUpSessionError(KubernetesBaseException):
    def __init__(self, code, file=None, original_exception=None, message=None):
        super().__init__(code, file, original_exception, message)


class KubernetesAPIError(KubernetesBaseException):
    def __init__(self, code, file=None, original_exception=None, message=None):
        super().__init__(code, file, original_exception, message)


class KubernetesTimeoutError(KubernetesBaseException):
    def __init__(self, code, file=None, original_exception=None, message=None):
        super().__init__(code, file, original_exception, message)
