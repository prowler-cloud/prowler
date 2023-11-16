# Custom metadata

In certain organizations, the severity of specific checks might differ from the default values defined. For instance, while `s3_bucket_level_public_access_block` could be deemed critical for some organizations, others might assign a different severity level.

The custom metadata option offers a means to override default metadata set by Prowler

You can utilize `--custom-checks-metadata-file` followed by the path to your custom checks metadata YAML file.

## Custom Checks Metadata Yaml File Syntax

    CustomChecksMetadata:
    aws:
        Checks:
        "s3_bucket_level_public_access_block":
            Severity: "high"
        "s3_bucket_no_mfa_delete":
            Severity: "low"



## Handling Multiple Providers

    CustomChecksMetadata:
    aws:
        Checks:
        "s3_bucket_level_public_access_block":
            Severity: "high"
        "s3_bucket_no_mfa_delete":
            Severity: "low"
    azure:
        Checks:
        "storage_ensure_minimum_tls_version_12":
            Severity: "high"



Executing the following command will assess all checks and generate a report while overriding the metadata for those checks:
```sh
prowler aws --custom-checks-metadata-file path/to/custom/metadata
```

This customization feature enables organizations to tailor the severity of specific checks based on their unique requirements, providing greater flexibility in security assessment and reporting.
