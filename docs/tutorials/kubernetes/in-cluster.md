# In-Cluster Execution

For in-cluster execution, you can use the supplied yaml files inside `/kubernetes`:

* [prowler-sa.yaml](https://github.com/prowler-cloud/prowler/blob/master/kubernetes/prowler-sa.yaml)
* [job.yaml](https://github.com/prowler-cloud/prowler/blob/master/kubernetes/job.yaml)
* [prowler-role.yaml](https://github.com/prowler-cloud/prowler/blob/master/kubernetes/prowler-role.yaml)
* [prowler-rolebinding.yaml](https://github.com/prowler-cloud/prowler/blob/master/kubernetes/prowler-rolebinding.yaml)

They can be used to run Prowler as a job within a new Prowler namespace:

```console
kubectl apply -f kubernetes/prowler-sa.yaml
kubectl apply -f kubernetes/job.yaml
kubectl apply -f kubernetes/prowler-role.yaml
kubectl apply -f kubernetes/prowler-rolebinding.yaml
kubectl get pods --namespace prowler-ns --> prowler-XXXXX
kubectl logs prowler-XXXXX --namespace prowler-ns
```

???+ note
    By default, `prowler` will scan all namespaces in your active Kubernetes context. Use the [`--namespace`](https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/kubernetes/namespace/) flag to specify the namespace(s) to be scanned.

???+ tip "Identifying the cluster in reports"
    When running in in-cluster mode, the Kubernetes API does not expose the actual cluster name by default.

    To uniquely identify the cluster in logs and reports, you can:

    - Use the `--cluster-name` flag to manually set the cluster name:
    ```bash
    prowler -p kubernetes --cluster-name production-cluster
    ```
    - Or set the `CLUSTER_NAME` environment variable:
    ```yaml
    env:
        - name: CLUSTER_NAME
        value: production-cluster
    ```
