"""Factory for auto-detecting registry type and returning the appropriate adapter."""

from __future__ import annotations

import re

from prowler.providers.image.lib.registry.dockerhub_adapter import DockerHubAdapter
from prowler.providers.image.lib.registry.oci_adapter import OciRegistryAdapter

_DOCKER_HUB_PATTERN = re.compile(
    r"^(https?://)?(docker\.io|registry-1\.docker\.io)(/|$)", re.IGNORECASE
)
_ECR_PATTERN = re.compile(
    r"^(https?://)?\d+\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com(/|$)", re.IGNORECASE
)


def create_registry_adapter(
    registry_url, username=None, password=None, token=None, verify_ssl=True
):
    """Auto-detect registry type from URL and return the appropriate adapter."""
    if _DOCKER_HUB_PATTERN.search(registry_url):
        return DockerHubAdapter(
            registry_url=registry_url,
            username=username,
            password=password,
            token=token,
            verify_ssl=verify_ssl,
        )
    return OciRegistryAdapter(
        registry_url=registry_url,
        username=username,
        password=password,
        token=token,
        verify_ssl=verify_ssl,
    )


def detect_registry_type(registry_url):
    """Return a string identifying the detected registry type."""
    if _DOCKER_HUB_PATTERN.search(registry_url):
        return "dockerhub"
    if _ECR_PATTERN.search(registry_url):
        return "ecr"
    return "oci"
