# Create a Custom Output Format

## Introduction

Prowler can generate outputs in multiple formats, allowing users to customize the way findings are presented. This is particularly useful when integrating Prowler with third-party tools, creating specialized reports, or simply tailoring the data to meet specific requirements. A custom output format gives you the flexibility to extract and display only the most relevant information in the way you need it.

* Prowler organizes its outputs in the `/lib/outputs` directory. Each format (e.g., JSON, CSV, HTML) is implemented as a Python class.
* Outputs are generated based on findings collected during a scan. Each finding is represented as a structured dictionary containing details like resource IDs, severities, descriptions, and more.
* Consult the [Prowler Developer Guide](https://docs.prowler.com/projects/prowler-open-source/en/latest/) to understand how Prowler works and the way that you can create it with the desired output!
* Identify the best approach for the specific output you’re targeting.

## Steps to Create a Custom Output Format

### Schema

* Output Class:
    * Create a class that encapsulates attributes and methods for the output.
    The following is the code for the `CSV` class:
    ```python title="CSV Class"
    class CSV(Output):
    def transform(self, findings: List[Finding]) -> None:
        """Transforms the findings into the CSV format.

        Args:
            findings (list[Finding]): a list of Finding objects

        """
    ...
    ```
* Transform Method:
    * This method will transform the findings provided by Prowler to a specific format.
    The following is the code for the `transform` method for the `CSV` class:
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
* Batch Write Data To File Method:
    * This method will write the modeled object to a file.
    The following is the code for the `batch_write_data_to_file` method for the `CSV` class:
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

### Integration With The Current Code

Once that the desired output format is created it has to be integrated with Prowler. Take a look at the the usage from the current supported output in order to add the new one.
Here is an example of the CSV output creation inside [prowler code](https://github.com/prowler-cloud/prowler/blob/master/prowler/__main__.py):
```python title="CSV creation"
if mode == "csv":
    csv_output = CSV(
        findings=finding_outputs,
        create_file_descriptor=True,
        file_path=f"{filename}{csv_file_suffix}",
    )
    generated_outputs["regular"].append(csv_output)
    # Write CSV Finding Object to file
    csv_output.batch_write_data_to_file()
```

### Testing

* Verify that Prowler’s findings are accurately writed in the desired output format.
* Simulate edge cases to ensure robust error handling.

### Documentation

* Provide clear, detailed documentation for your output:
    * Setup instructions, including any required dependencies.
    * Configuration details.
    * Example use cases and troubleshooting tips.
* Good documentation ensures maintainability and simplifies onboarding for new users.
