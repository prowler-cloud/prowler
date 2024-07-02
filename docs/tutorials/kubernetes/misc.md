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
