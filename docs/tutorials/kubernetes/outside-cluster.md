# External Access

For non in-cluster execution, you can provide the location of the [kubeconfig](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/) file with the following argument:

```console
prowler kubernetes --kubeconfig-file path
```
???+ note
    If no `--kubeconfig-file` is provided, Prowler will use the default KubeConfig file location (`~/.kube/config`).
