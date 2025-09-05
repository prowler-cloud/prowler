# Tag-based scan

Prowler provides the capability to scan only resources containing specific tags. To execute this, use the designated flag `--resource-tags` followed by the tags `Key=Value`, separated by spaces.

```
prowler aws --resource-tags Environment=dev Project=prowler
```

This configuration scans only resources that contain both specified tags.
