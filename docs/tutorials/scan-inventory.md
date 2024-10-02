# Scan Inventory

The scan-inventory feature is a tool that generates a JSON report within the `/output/inventory/<provider>` directory and the scanned service. This feature allows you to perform a inventory of the resources existing in your provider that are scanned by Prowler.

## Usage

To use the scan-inventory feature, run Prowler with the `--scan-inventory` option. For example:

```
prowler <provider> --scan-inventory
```

This will generate a JSON report within the `/output/inventory/<provider>` directory and the scanned service.

## Output Directory Contents

The contents of the `/output/<provider>` directory and the scanned service depend on the Prowler execution. This directory contains all the information gathered during scanning, including a JSON report containing all the gathered information.

## Limitations

The scan-inventory feature has some limitations. For example:

* It is only available for the AWS provider.
* It only contains the information retrieved by Prowler during the execution.

## Example

Here's an example of how to use the scan-inventory feature and the contents of the `/output/inventory/<provider>` directory and the scanned service:

`prowler aws -s ec2 --scan-inventory`

```
/output/inventory/aws directory
   |
   |-- ec2
   |    |
   |    |-- ec2_output.json
```
In this example, Prowler is run with the `-s ec2` and `--scan-inventory` options for the AWS provider. The `/output/inventory/aws` directory contains a JSON report showing all the information gathered during scanning.
