Scan report generation parses each resource's metadata once per batch and sanitizes it once per finding, so providers with very large resource metadata no longer exhaust the worker memory
