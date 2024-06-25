# Non in-cluster execution

For non in-cluster execution, you can provide the location of the [kubeconfig](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/) file with the following argument:

```console
prowler kubernetes --kubeconfig-file /path/to/kubeconfig
```
???+ note
    If no `--kubeconfig-file` is provided, Prowler will use the default KubeConfig file location (`~/.kube/config`).

???+ note
    `prowler` will scan the active Kubernetes context by default. Use the [`--context`](https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/kubernetes/context/) flag to specify the context to be scanned.

???+ note
    By default, `prowler` will scan all namespaces in your active Kubernetes context. Use the [`--namespace`](https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/kubernetes/namespace/) flag to specify the namespace(s) to be scanned.
