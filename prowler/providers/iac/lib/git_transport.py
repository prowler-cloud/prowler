"""dulwich HTTP transport that keeps redirect destinations inside the SSRF guard."""

from __future__ import annotations

import os
from urllib.parse import urlparse, urlunparse

import urllib3
from dulwich.client import default_urllib3_manager, get_transport_and_path
from dulwich.config import Config, StackedConfig, apply_instead_of, env_config

from prowler.lib.network.ssrf import validate_outbound_url

# shared so the connection test and the clone cannot disagree about what a
# tenant is allowed to configure
ALLOWED_SCHEMES = ("http", "https", "ssh", "git")


class _GuardedRedirects:
    def urlopen(self, method, url, redirect=True, **kwargs):
        # urllib3 recurses through self.urlopen once per hop, so validating here
        # covers the whole chain; dulwich adopts a hop as the new repository base
        validate_outbound_url(url)
        return super().urlopen(method, url, redirect=redirect, **kwargs)


class GuardedPoolManager(_GuardedRedirects, urllib3.PoolManager):
    """Pool manager that validates every destination it is asked to open."""


class GuardedProxyManager(_GuardedRedirects, urllib3.ProxyManager):
    """Proxy manager that validates every destination it is asked to open."""


def git_config() -> Config:
    """Stacked git configuration, with the GIT_* overrides porcelain applies."""
    config = StackedConfig.default()
    override = env_config(os.environ)
    if override is not None:
        config.backends.insert(0, override)
    return config


def effective_url(config: Config, url: str) -> str:
    """URL after git's ``url.*.insteadOf`` rewriting, which is what picks the transport.

    A rewrite can turn a validated public URL into an ``ssh://`` one on a private
    host, so the guard has to see this form and not the supplied one.
    """
    return apply_instead_of(config, url, push=False)


def proxy_base_url(url: str) -> str:
    """Scheme and host only, for dulwich's ``no_proxy`` and ``http.<url>.*`` matching."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    return urlunparse((parsed.scheme, netloc, "", "", "", ""))


def guarded_pool_manager(config: Config, base_url: str) -> urllib3.PoolManager:
    """dulwich HTTP manager whose every request, redirects included, is validated.

    ``base_url`` is what dulwich uses to honour ``no_proxy`` and the per-URL
    ``http.*`` settings, so building the manager without it silently drops them.
    """
    return default_urllib3_manager(
        config,
        base_url=base_url,
        pool_manager_cls=GuardedPoolManager,
        proxy_manager_cls=GuardedProxyManager,
    )


def ls_remote(url: str):
    """porcelain.ls_remote with the guarded manager, which porcelain cannot be given.

    The supplied URL is handed to dulwich, not the rewritten one: ``insteadOf`` is a
    single substitution, so rewriting twice can land on a third destination.
    """
    config = git_config()
    target = effective_url(config, url)
    validate_outbound_url(target, allowed_schemes=ALLOWED_SCHEMES)
    client, path = get_transport_and_path(
        url,
        config=config,
        pool_manager=guarded_pool_manager(config, proxy_base_url(target)),
    )
    return client.get_refs(path.encode() if isinstance(path, str) else path)
