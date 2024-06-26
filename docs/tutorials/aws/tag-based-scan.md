# Tags-based Scan

Prowler allows you to scan only the resources that contain specific tags. This can be done with the flag `--resource-tags` followed by the tags `Key=Value` separated by space:

```
prowler aws --resource-tags Environment=dev Project=prowler
```

This example will only scan the resources that contains both tags.
