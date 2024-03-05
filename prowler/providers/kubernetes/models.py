from dataclasses import dataclass

from kubernetes import client

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


@dataclass
class KubernetesIdentityInfo:
    context: str
    cluster: str
    user: str


@dataclass
class KubernetesSession:
    """
    KubernetesSession stores the Kubernetes session's configuration.

    """

    api_client: client.ApiClient
    context: dict


class KubernetesOutputOptions(ProviderOutputOptions):
    def __init__(self, arguments, bulk_checks_metadata, identity):
        # First call ProviderOutputOptions init
        super().__init__(arguments, bulk_checks_metadata)
        # TODO move the below if to ProviderOutputOptions
        # Check if custom output filename was input, if not, set the default
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            self.output_filename = (
                f"prowler-output-{identity.context}-{output_file_timestamp}"
            )
        else:
            self.output_filename = arguments.output_filename
