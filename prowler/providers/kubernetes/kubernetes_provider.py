import os
import sys

from kubernetes import client, config

from prowler.lib.logger import logger


class Kubernetes_Provider:
    def __init__(
        self,
        kubeconfig_file: str,
        context: list,
    ):
        logger.info("Instantiating Kubernetes Provider ...")
        self.context = context
        self.api_client = self.__set_credentials__(kubeconfig_file, context)
        if not self.api_client:
            logger.critical("Failed to set up a Kubernetes session.")
            sys.exit(1)

    def __set_credentials__(self, kubeconfig_file, context):
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

    def get_credentials(self):
        return self.api_client, self.context
