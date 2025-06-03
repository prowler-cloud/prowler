# Miscellaneous

## Context Filtering in Prowler

Prowler will scan the active Kubernetes context by default.

To specify a different Kubernetes context for scanning, use the `--context` flag followed by the desired context name, for example:

```console
prowler --context my-context
```

This ensures that Prowler analyzes the selected context or cluster for vulnerabilities and misconfigurations.

## Namespace Filtering

By default, `prowler` scans all namespaces within the specified context.

To limit the scan to specific namespaces, use the `--namespace` flag followed by the desired namespace names, separated by spaces: for example:

```console
prowler --namespace namespace1 namespace2
```
