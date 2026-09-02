`--registry-insecure` now propagates to Trivy via `TRIVY_INSECURE`, so images in registries with self-signed certificates can be pulled and scanned, not just enumerated
