from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 4000 to 4999 are reserved for Kubernetes exceptions
class KubernetesBaseException(ProwlerException):
    """Base class for Kubernetes errors."""

    KUBERNETES_ERROR_CODES = {
        (4000, "KubernetesCloudResourceManagerAPINotUsedError"): {
            "message": "Cloud Resource Manager API is not enabled, blocking access to necessary resources.",
            "remediation": "Refer to the Kubernetes documentation to enable the Cloud Resource Manager API: https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
        },
        (4001, "KubernetesSetUpSessionError"): {
            "message": "Failed to establish a Kubernetes session, preventing further actions.",
            "remediation": "Verify your session setup, including credentials and Kubernetes cluster configuration. Refer to this guide for proper setup: https://kubernetes.io/docs/tasks/access-application-cluster/configure-access-multiple-clusters/",
        },
        (4002, "KubernetesAPIError"): {
            "message": "An error occurred while interacting with the Kubernetes API.",
            "remediation": "Check the API request and ensure it is properly formatted. Refer to the Kubernetes API documentation for guidance: https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.22/",
        },
        (4003, "KubernetesTimeoutError"): {
            "message": "The request to the Kubernetes API timed out.",
            "remediation": "Check the network connection and the Kubernetes API server status. For information on troubleshooting timeouts, refer to the Kubernetes documentation: https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.22/#-strong-timeout-strong-",
        },
        (4004, "KubernetesError"): {
            "message": "An error occurred in the Kubernetes provider.",
            "remediation": "Check the provider code and configuration to identify the issue. For more information on troubleshooting Kubernetes providers, refer to the Kubernetes documentation: https://kubernetes.io/docs/reference/",
        },
        (4005, "KubernetesInvalidProviderIdError"): {
            "message": "The provider ID is invalid.",
            "remediation": "Check the provider ID and ensure it is correctly formatted. Refer to the Kubernetes documentation for guidance on provider IDs: https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
        },
        (4006, "KubernetesInvalidKubeConfigFileError"): {
            "message": "The provided kube-config is invalid.",
            "remediation": "Review the kube-config and the attached error to get more details. Please, refer to the Kubernetes config documentation: https://kubernetes.io/docs/reference/config-api/kubeconfig.v1/#Config",
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
            source=provider,
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class KubernetesError(KubernetesBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(4004, file, original_exception, message)


class KubernetesCloudResourceManagerAPINotUsedError(KubernetesBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(4000, file, original_exception, message)


class KubernetesSetUpSessionError(KubernetesBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(4001, file, original_exception, message)


class KubernetesAPIError(KubernetesBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(4002, file, original_exception, message)


class KubernetesTimeoutError(KubernetesBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(4003, file, original_exception, message)


class KubernetesInvalidProviderIdError(KubernetesBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(4005, file, original_exception, message)


class KubernetesInvalidKubeConfigFileError(KubernetesBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(4006, file, original_exception, message)
