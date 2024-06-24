# In-Cluster Execution

For in-cluster execution, you can use the supplied yaml files inside `/kubernetes`:

* [job.yaml](https://github.com/prowler-cloud/prowler/blob/master/kubernetes/job.yaml)
* [prowler-role.yaml](https://github.com/prowler-cloud/prowler/blob/master/kubernetes/prowler-role.yaml)
* [prowler-rolebinding.yaml](https://github.com/prowler-cloud/prowler/blob/master/kubernetes/prowler-rolebinding.yaml)

They can be used to run Prowler as a job within a new Prowler namespace:

```console
kubectl apply -f kubernetes/job.yaml
kubectl apply -f kubernetes/prowler-role.yaml
kubectl apply -f kubernetes/prowler-rolebinding.yaml
kubectl get pods --namespace prowler-ns --> prowler-XXXXX
kubectl logs prowler-XXXXX --namespace prowler-ns
```

???+ note
    By default, `prowler` will scan all namespaces in your active Kubernetes context. Use the flag `--context` to specify the context to be scanned and `--namespaces` to specify the namespaces to be scanned.

## Context Flag

To specify the Kubernetes context to be scanned, use the `--context` flag followed by the desired context name. For example:

```console
prowler --context my-context
```

This will ensure that Prowler scans the specified context for vulnerabilities and misconfigurations.

## Namespace Flag

To specify the namespace(s) to be scanned, use the `--namespace` flag followed by the desired namespace(s) sepparated by spaces. For example:
```console
prowler --namespace namespace1 namespace2
```
