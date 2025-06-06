# Create a Custom Output Format

## Introduction

Prowler supports multiple output formats, allowing users to tailor findings presentation to their needs. Custom output formats are valuable when integrating Prowler with third-party tools, generating specialized reports, or adapting data for specific workflows. By defining a custom output format, users can refine how findings are structured, extracting and displaying only the most relevant information.

- Output Organization in Prowler

    Prowler outputs are managed within the `/lib/outputs` directory. Each format—such as JSON, CSV, HTML—is implemented as a Python class.

- Outputs are generated based on scan findings, which are stored as structured dictionaries containing details such as:

    - Resource IDs

    - Severities

    - Descriptions

    - Other relevant metadata

- Creation Guidelines

    Refer to the [Prowler Developer Guide](https://docs.prowler.com/projects/prowler-open-source/en/latest/) for insights into Prowler’s architecture and best practices for creating custom outputs.

- Identify the most suitable integration method for the output being targeted.

## Steps to Create a Custom Output Format

### Schema

- Output Class:

    - The class must inherit from `Output`. Review the [Output Class](https://github.com/prowler-cloud/prowler/blob/master/prowler/lib/outputs/output.py).

    - Create a class that encapsulates the required attributes and methods for interacting with the target platform. Below the code for the `CSV` class is presented:

    ```python title="CSV Class"
    class CSV(Output):
        def transform(self, findings: List[Finding]) -> None:
            """Transforms the findings into the CSV format.

            Args:
                findings (list[Finding]): a list of Finding objects

            """
        ...
    ```


    - Transform Method:

        - This method will transform the findings provided by Prowler to a specific format.

        #### Method Implementation

        The following example demonstrates the `transform` method for the `CSV` class:

        ```python title="Transform"
        def transform(self, findings: List[Finding]) -> None:
            """Transforms the findings into the CSV format.

            Args:
                findings (list[Finding]): a list of Finding objects

            """
            try:
                for finding in findings:
                    finding_dict = {}
                    finding_dict["AUTH_METHOD"] = finding.auth_method
                    finding_dict["TIMESTAMP"] = finding.timestamp
                    finding_dict["ACCOUNT_UID"] = finding.account_uid
                    finding_dict["ACCOUNT_NAME"] = finding.account_name
                    finding_dict["ACCOUNT_EMAIL"] = finding.account_email
                    finding_dict["ACCOUNT_ORGANIZATION_UID"] = (
                        finding.account_organization_uid
                    )
                    finding_dict["ACCOUNT_ORGANIZATION_NAME"] = (
                        finding.account_organization_name
                    )
                    finding_dict["ACCOUNT_TAGS"] = unroll_dict(
                        finding.account_tags, separator=":"
                    )
                    finding_dict["FINDING_UID"] = finding.uid
                    finding_dict["PROVIDER"] = finding.metadata.Provider
                    finding_dict["CHECK_ID"] = finding.metadata.CheckID
                    finding_dict["CHECK_TITLE"] = finding.metadata.CheckTitle
                    finding_dict["CHECK_TYPE"] = unroll_list(finding.metadata.CheckType)
                    finding_dict["STATUS"] = finding.status.value
                    finding_dict["STATUS_EXTENDED"] = finding.status_extended
                    finding_dict["MUTED"] = finding.muted
                    finding_dict["SERVICE_NAME"] = finding.metadata.ServiceName
                    finding_dict["SUBSERVICE_NAME"] = finding.metadata.SubServiceName
                    finding_dict["SEVERITY"] = finding.metadata.Severity.value
                    finding_dict["RESOURCE_TYPE"] = finding.metadata.ResourceType
                    finding_dict["RESOURCE_UID"] = finding.resource_uid
                    finding_dict["RESOURCE_NAME"] = finding.resource_name
                    finding_dict["RESOURCE_DETAILS"] = finding.resource_details
                    finding_dict["RESOURCE_TAGS"] = unroll_dict(finding.resource_tags)
                    finding_dict["PARTITION"] = finding.partition
                    finding_dict["REGION"] = finding.region
                    finding_dict["DESCRIPTION"] = finding.metadata.Description
                    finding_dict["RISK"] = finding.metadata.Risk
                    finding_dict["RELATED_URL"] = finding.metadata.RelatedUrl
                    finding_dict["REMEDIATION_RECOMMENDATION_TEXT"] = (
                        finding.metadata.Remediation.Recommendation.Text
                    )
                    finding_dict["REMEDIATION_RECOMMENDATION_URL"] = (
                        finding.metadata.Remediation.Recommendation.Url
                    )
                    finding_dict["REMEDIATION_CODE_NATIVEIAC"] = (
                        finding.metadata.Remediation.Code.NativeIaC
                    )
                    finding_dict["REMEDIATION_CODE_TERRAFORM"] = (
                        finding.metadata.Remediation.Code.Terraform
                    )
                    finding_dict["REMEDIATION_CODE_CLI"] = (
                        finding.metadata.Remediation.Code.CLI
                    )
                    finding_dict["REMEDIATION_CODE_OTHER"] = (
                        finding.metadata.Remediation.Code.Other
                    )
                    finding_dict["COMPLIANCE"] = unroll_dict(
                        finding.compliance, separator=": "
                    )
                    finding_dict["CATEGORIES"] = unroll_list(finding.metadata.Categories)
                    finding_dict["DEPENDS_ON"] = unroll_list(finding.metadata.DependsOn)
                    finding_dict["RELATED_TO"] = unroll_list(finding.metadata.RelatedTo)
                    finding_dict["NOTES"] = finding.metadata.Notes
                    finding_dict["PROWLER_VERSION"] = finding.prowler_version
                    self._data.append(finding_dict)
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        ```

    - Batch Write Data To File Method:

        - This method will write the modeled object to a file.

        #### Method Implementation

        The following example demonstrates the `batch_write_data_to_file` method for the `CSV` class:

        ```python title="Batch Write Data To File"
        def batch_write_data_to_file(self) -> None:
            """Writes the findings to a file using the CSV format using the `Output._file_descriptor`."""
            try:
                if (
                    getattr(self, "_file_descriptor", None)
                    and not self._file_descriptor.closed
                    and self._data
                ):
                    csv_writer = DictWriter(
                        self._file_descriptor,
                        fieldnames=self._data[0].keys(),
                        delimiter=";",
                    )
                    csv_writer.writeheader()
                    for finding in self._data:
                        csv_writer.writerow(finding)
                    self._file_descriptor.close()
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        ```

### Integrating the Custom Output Format into Prowler

Once the custom output format is created, it must be integrated into Prowler to ensure compatibility with the existing architecture.

#### Reviewing Current Supported Outputs

Before implementing the new output format, examine the usage of currently supported formats to understand their structure and integration approach. Example: CSV Output Creation in Prowler

Below is an example of how Prowler generates and processes CSV output within its [codebase](https://github.com/prowler-cloud/prowler/blob/master/prowler/__main__.py):

```python title="CSV creation"
if mode == "csv":
    csv_output = CSV(
        findings=finding_outputs,
        create_file_descriptor=True,
        file_path=f"{filename}{csv_file_suffix}",
    )
    generated_outputs["regular"].append(csv_output)
    # Write CSV Finding Object to file.
    csv_output.batch_write_data_to_file()
```

### Testing

* Verify that Prowler’s findings are accurately typed in the desired output format.

* Error Handling – Simulate edge cases to assess robustness and failure recovery mechanisms.

### Documentation

* Ensure the following elements are included:

    * Setup Instructions – List all necessary dependencies and installation steps.
    * Configuration details.
    * Example Use Cases – Provide practical scenarios demonstrating functionality.
    * Troubleshooting Guide – Document common issues and resolution steps.

* Comprehensive and clear documentation improves maintainability and simplifies onboarding of new users.
