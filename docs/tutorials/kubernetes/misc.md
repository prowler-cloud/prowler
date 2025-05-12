# Miscellaneous

## Context Filtering

Prowler will scan the active Kubernetes context by default.

To specify the Kubernetes context to be scanned, use the `--context` flag followed by the desired context name. For example:

```console
prowler --context my-context
```

This will ensure that Prowler scans the specified context/cluster for vulnerabilities and misconfigurations.

## Namespace Filtering

By default, `prowler` will scan all namespaces in the context you specify.

To specify the namespace(s) to be scanned, use the `--namespace` flag followed by the desired namespace(s) separated by spaces. For example:

```console
prowler --namespace namespace1 namespace2
```

## Proxy and TLS Verification

If your Kubernetes cluster is only accessible via an internal proxy, Prowler will respect the `HTTPS_PROXY` or `https_proxy` environment variable:

```console
export HTTPS_PROXY=http://my.internal.proxy:8888
prowler kubernetes ...
```

If you need to skip TLS verification for internal proxies, you can set the `K8S_SKIP_TLS_VERIFY` environment variable:

```console
export K8S_SKIP_TLS_VERIFY=true
prowler kubernetes ...
```

This will allow Prowler to connect to the cluster even if the proxy uses a self-signed certificate.

These environment variables are supported both when using an external `kubeconfig` and in in-cluster mode.
