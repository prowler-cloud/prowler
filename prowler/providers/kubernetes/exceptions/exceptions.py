from prowler.exceptions.exceptions import ProwlerException


class KubernetesBaseException(ProwlerException):
    """Base class for Kubernetes errors."""

    KUBERNETES_ERROR_CODES = {
        (1925, "KubernetesCloudResourceManagerAPINotUsedError"): {
            "message": "Cloud Resource Manager API is not enabled, blocking access to necessary resources.",
            "remediation": "Refer to the Kubernetes documentation to enable the Cloud Resource Manager API: https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
            "file": "{file}",
            "provider": "{provider}",
        },
        (1926, "KubernetesSetUpSessionError"): {
            "message": "Failed to establish a Kubernetes session, preventing further actions.",
            "remediation": "Verify your session setup, including credentials and Kubernetes cluster configuration. Refer to this guide for proper setup: https://kubernetes.io/docs/tasks/access-application-cluster/configure-access-multiple-clusters/",
            "file": "{file}",
            "provider": "{provider}",
        },
        (1927, "KubernetesSearchAndSaveRolesError"): {
            "message": "An error occurred while searching for and saving Kubernetes roles.",
            "remediation": "Ensure the roles are correctly configured and exist in the cluster. For more information on managing Kubernetes roles, visit: https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
            "file": "{file}",
            "provider": "{provider}",
        },
        (1928, "KubernetesGetContextUserRolesError"): {
            "message": "Failed to retrieve context user roles, possibly due to misconfiguration.",
            "remediation": "Check the user roles in the current context and ensure they are correctly set up. Refer to the Kubernetes documentation for guidance: https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles",
            "file": "{file}",
            "provider": "{provider}",
        },
        (1929, "KubernetesGetAllNamespacesError"): {
            "message": "Error occurred while fetching all namespaces in the Kubernetes cluster.",
            "remediation": "Verify that namespaces are correctly configured and accessible. Follow this guide to troubleshoot namespace issues: https://kubernetes.io/docs/tasks/administer-cluster/namespaces-walkthrough/",
            "file": "{file}",
            "provider": "{provider}",
        },
    }

    def __init__(self, code, provider="Kubernetes", file=None, original_exception=None):
        error_info = self.KUBERNETES_ERROR_CODES.get((code, self.__class__.__name__))
        super().__init__(code, provider, file, original_exception, error_info)


class KubernetesCloudResourceManagerAPINotUsedError(KubernetesBaseException):
    def __init__(self, code, file=None, original_exception=None, error_info=None):
        super().__init__(code, file, original_exception, error_info)


class KubernetesSetUpSessionError(KubernetesBaseException):
    def __init__(self, code, file=None, original_exception=None, error_info=None):
        super().__init__(code, file, original_exception, error_info)


class KubernetesSearchAndSaveRolesError(KubernetesBaseException):
    def __init__(self, code, file=None, original_exception=None, error_info=None):
        super().__init__(code, file, original_exception, error_info)


class KubernetesGetContextUserRolesError(KubernetesBaseException):
    def __init__(self, code, file=None, original_exception=None, error_info=None):
        super().__init__(code, file, original_exception, error_info)


class KubernetesGetAllNamespacesError(KubernetesBaseException):
    def __init__(self, code, file=None, original_exception=None, error_info=None):
        super().__init__(code, file, original_exception, error_info)
