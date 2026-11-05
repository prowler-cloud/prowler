import yaml

from prowler.lib.logger import logger
from prowler.providers.kubernetes.kubernetes_provider import KubernetesProvider
from prowler.providers.kubernetes.lib.service.service import KubernetesService
from prowler.providers.kubernetes.services.core.core_client import core_client


class Kubelet(KubernetesService):
    def __init__(self, provider: KubernetesProvider):
        super().__init__(provider)
        self.client = core_client

        self.kubelet_config_maps = self._get_kubelet_config_maps()

    def _get_kubelet_config_maps(self):
        """Collect the ConfigMaps whose name starts with `kubelet-config`.

        Each ConfigMap is parsed independently: one with malformed YAML is
        logged and skipped so the remaining ones are still evaluated, and one
        without kubelet data is kept with empty arguments so the checks report
        the missing settings. The result is always a list.

        Returns:
            list: Matching ConfigMaps with their `kubelet_args` parsed.
        """
        kubelet_config_maps = []
        try:
            for cm in self.client.config_maps.values():
                if not cm.name.startswith("kubelet-config"):
                    continue
                try:
                    cm.kubelet_args = yaml.safe_load((cm.data or {}).get("kubelet", ""))
                    if not isinstance(cm.kubelet_args, dict):
                        cm.kubelet_args = {}
                    kubelet_config_maps.append(cm)
                except Exception as error:
                    logger.error(
                        f"{cm.namespace}/{cm.name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return kubelet_config_maps
