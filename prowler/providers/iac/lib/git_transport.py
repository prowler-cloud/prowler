"""dulwich HTTP transport that keeps redirect destinations inside the SSRF guard."""

from __future__ import annotations

import os

import urllib3
from dulwich.client import default_urllib3_manager, get_transport_and_path
from dulwich.config import Config, StackedConfig, env_config

from prowler.lib.network.ssrf import validate_outbound_url


class _GuardedRedirects:
    def urlopen(self, method, url, redirect=True, **kwargs):
        # urllib3 recurses through self.urlopen once per hop, so validating here
        # covers the whole redirect chain and not only the supplied URL. dulwich
        # adopts a redirect's destination as the new repository base.
        validate_outbound_url(url)
        return super().urlopen(method, url, redirect=redirect, **kwargs)


class GuardedPoolManager(_GuardedRedirects, urllib3.PoolManager):
    """Pool manager that validates every destination it is asked to open."""


class GuardedProxyManager(_GuardedRedirects, urllib3.ProxyManager):
    """Proxy manager that validates every destination it is asked to open."""


def git_config() -> Config:
    """Stacked git configuration, with the GIT_* environment overrides porcelain applies."""
    config = StackedConfig.default()
    override = env_config(os.environ)
    if override is not None:
        config.backends.insert(0, override)
    return config


def guarded_pool_manager(config: Config | None = None) -> urllib3.PoolManager:
    """dulwich HTTP manager whose every request, redirects included, is validated."""
    return default_urllib3_manager(
        config if config is not None else git_config(),
        pool_manager_cls=GuardedPoolManager,
        proxy_manager_cls=GuardedProxyManager,
    )


def ls_remote(url: str):
    """porcelain.ls_remote with the guarded manager, which porcelain cannot be given."""
    config = git_config()
    client, path = get_transport_and_path(
        url, config=config, pool_manager=guarded_pool_manager(config)
    )
    return client.get_refs(path.encode() if isinstance(path, str) else path)
