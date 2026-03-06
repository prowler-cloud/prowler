# Minimal Installation Example

This example demonstrates a minimal installation of Prowler in a Kubernetes cluster.

## Installation

To install Prowler using this example:

1. First, create the required secret:
```bash
# Edit secret.yaml and set secure values before applying
kubectl apply -f secret.yaml
```

1. Install the chart using the base values file:
```bash
# Basic installation
helm install prowler prowler/prowler-app -f values.yaml
```

## Configuration

The example contains the following configuration files:

### `secret.yaml`
Contains all required secrets for the Prowler installation. **Must be applied before installing the Helm chart**. Make sure to replace all placeholder values with secure values before applying.

### `values.yaml`
```yaml
ui:
  # Note: You should set either `authUrl` if you use prowler behind a proxy or enable `ingress`.

  # Example with authUrl:
  # authUrl: example.prowler.com

  # Example with ingress:
  ingress:
    enabled: true
    hosts:
      - host: example.prowler.com
        paths:
          - path: /
            pathType: ImplementationSpecific
```

Make sure to adjust the hostname in the values file to match your environment before installing.
