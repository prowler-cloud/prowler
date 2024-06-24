# In-Cluster Execution

For in-cluster execution, you can use the supplied yaml to run Prowler as a job within a new Prowler namespace:

```console
kubectl apply -f kubernetes/job.yaml
kubectl apply -f kubernetes/prowler-role.yaml
kubectl apply -f kubernetes/prowler-rolebinding.yaml
kubectl get pods --namespace prowler-ns --> prowler-XXXXX
kubectl logs prowler-XXXXX --namespace prowler-ns
```

???+ note
    By default, `prowler` will scan all namespaces in your active Kubernetes context. Use the flag `--context` to specify the context to be scanned and `--namespaces` to specify the namespaces to be scanned.
