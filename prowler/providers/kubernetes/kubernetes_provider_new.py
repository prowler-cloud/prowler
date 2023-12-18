import os
import sys
from typing import Any, Optional

from colorama import Fore, Style
from kubernetes import client, config

from prowler.lib.logger import logger
from prowler.providers.common.provider import CloudProvider


class KubernetesProvider(CloudProvider):
    session: client.ApiClient
    context: Optional[str]
    audit_resources: Optional[Any]
    audit_metadata: Optional[Any]
    audit_config: Optional[dict]

    def __init__(self, arguments):
        logger.info("Instantiating Kubernetes Provider ...")
        kubeconfig_file = arguments.kubeconfig_file
        self.context = arguments.context

        self.session = self.setup_session(kubeconfig_file, self.context)
        if not self.session:
            logger.critical("Failed to set up a Kubernetes session.")
            sys.exit(1)

        if not arguments.only_logs:
            self.print_credentials()

    def setup_session(self, kubeconfig_file, context):
        try:
            if kubeconfig_file:
                # Use kubeconfig file if provided
                config.load_kube_config(
                    config_file=os.path.abspath(kubeconfig_file), context=context
                )
            else:
                # Otherwise try to load in-cluster config
                config.load_incluster_config()

            return client.ApiClient()
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            sys.exit(1)

    def print_credentials(self):
        # Load the kubeconfig file
        kube_config = config.list_kube_config_contexts()

        if kube_config:
            # Get the current context
            current_context = kube_config[1].get("context")
            cluster_name = current_context.get("cluster")
            user_name = current_context.get("user")
            namespace = current_context.get("namespace", "default")

            report = f"""
This report is being generated using the Kubernetes configuration below:

Kubernetes Cluster: {Fore.YELLOW}[{cluster_name}]{Style.RESET_ALL}  User: {Fore.YELLOW}[{user_name}]{Style.RESET_ALL}  Namespace: {Fore.YELLOW}[{namespace}]{Style.RESET_ALL}
"""
            print(report)
        else:
            print("No Kubernetes configuration found.")
