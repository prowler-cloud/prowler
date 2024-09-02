from prowler.exceptions.exceptions import ProwlerException


class KubernetesBaseException(ProwlerException):
    """Base class for Kubernetes errors."""

    KUBERNETES_ERROR_CODES = {
        (1925, "KubernetesCloudResourceManagerAPINotUsedError"): {
            "message": "Cloud Resource Manager API not used",
            "remediation": "Enable the Cloud Resource Manager API for the project.",
            "file": "{file}",
            "provider": "Kubernetes",
        },
        (1926, "KubernetesSetUpSessionError"): {
            "message": "Error setting up session",
            "remediation": "Check the session setup and ensure it is properly set up.",
            "file": "{file}",
            "provider": "Kubernetes",
        },
        (1927, "KubernetesSearchAndSaveRolesError"): {
            "message": "Error searching and saving roles",
            "remediation": "Check the roles and ensure they are properly set up.",
            "file": "{file}",
            "provider": "Kubernetes",
        },
        (1928, "KubernetesGetContextUserRolesError"): {
            "message": "Error getting context user roles",
            "remediation": "Check the context user roles and ensure they are properly set up.",
            "file": "{file}",
            "provider": "Kubernetes",
        },
        (1929, "KubernetesGetAllNamespacesError"): {
            "message": "Error getting all namespaces",
            "remediation": "Check the namespaces and ensure they are properly set up.",
            "file": "{file}",
            "provider": "Kubernetes",
        },
    }


class KubernetesCloudResourceManagerAPINotUsedError(KubernetesBaseException):
    def __init__(
        self, code, provider=None, file=None, original_exception=None, error_info=None
    ):
        super().__init__(code, provider, file, original_exception, error_info)


class KubernetesSetUpSessionError(KubernetesBaseException):
    def __init__(
        self, code, provider=None, file=None, original_exception=None, error_info=None
    ):
        super().__init__(code, provider, file, original_exception, error_info)


class KubernetesSearchAndSaveRolesError(KubernetesBaseException):
    def __init__(
        self, code, provider=None, file=None, original_exception=None, error_info=None
    ):
        super().__init__(code, provider, file, original_exception, error_info)


class KubernetesGetContextUserRolesError(KubernetesBaseException):
    def __init__(
        self, code, provider=None, file=None, original_exception=None, error_info=None
    ):
        super().__init__(code, provider, file, original_exception, error_info)


class KubernetesGetAllNamespacesError(KubernetesBaseException):
    def __init__(
        self, code, provider=None, file=None, original_exception=None, error_info=None
    ):
        super().__init__(code, provider, file, original_exception, error_info)
