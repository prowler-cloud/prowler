# AWS Security Hub Integration with Prowler

Prowler natively supports **official integration** with [AWS Security Hub](https://aws.amazon.com/security-hub), allowing security findings to be sent directly.  This integration enables **Prowler** to import its findings into AWS Security Hub.

To activate the integration, follow these steps in at least one AWS region within your AWS account:

## Enabling AWS Security Hub for Prowler Integration

To enable the integration, follow these steps in **at least** one AWS region within your AWS account.

Since **AWS Security Hub** is a region-based service, it must be activated in each region where security findings need to be collected.

**Configuration Options**

AWS Security Hub can be enabled using either of the following methods:

???+ note
    Enabling this integration incurs costs in AWS Security Hub. Refer to [this information](https://aws.amazon.com/security-hub/pricing/) for details.

### Using the AWS Management Console

#### Enabling AWS Security Hub for Prowler Integration

If AWS Security Hub is already enabled, you can proceed to the [next section](#enable-prowler-integration).

1. Enable AWS Security Hub via Console: Open the **AWS Security Hub** console: https://console.aws.amazon.com/securityhub/.

2. Ensure you are in the correct AWS region, then select “**Go to Security Hub**”. ![](./img/enable.png)

3. In the “Security Standards” section, review the supported security standards. Select the checkbox for each standard you want to enable, or clear it to disable a standard.

4. Choose “**Enable Security Hub**”. ![](./img/enable-2.png)

#### Enabling Prowler Integration in AWS Security Hub

If the Prowler integration is already enabled in AWS Security Hub, you can proceed to the [next section](#send-findings) and begin sending findings.

Once **AWS Security Hub** is activated, **Prowler** must be enabled as partner integration to allow security findings to be sent to it.

1. Enabling AWS Security Hub via Console
Open the **AWS Security Hub** console: https://console.aws.amazon.com/securityhub/.

2. Select the “**Integrations**” tab from the right-side menu bar. ![](./img/enable-partner-integration.png)

3. Search for “_Prowler_” in the text search box and the **Prowler** integration will appear.

4. Click “**Accept Findings**” to authorize **AWS Security Hub** to receive findings from **Prowler**. ![](./img/enable-partner-integration-2.png)

5. A new modal will appear to confirm that the integration with **Prowler** is being enabled. ![](./img/enable-partner-integration-3.png)

6. Click “**Accept Findings**”, to authorize **AWS Security Hub** to receive findings from Prowler. ![](./img/enable-partner-integration-4.png)

### Using AWS CLI

To enable **AWS Security Hub** and integrate **Prowler**, execute the following AWS CLI commands:

**Step 1: Enable AWS Security Hub**

Run the following command to activate AWS Security Hub in the desired region:

```shell
aws securityhub enable-security-hub --region <region>
```

???+ note
    This command requires the `securityhub:EnableSecurityHub` permission. Ensure you set the correct AWS region where you want to enable AWS Security Hub.

**Step 2: Enable Prowler Integration**

Once **AWS Security Hub** is activated, **Prowler** must be enabled as partner integration to allow security findings to be sent to it. Run the following AWS CLI commands:

```shell
aws securityhub enable-import-findings-for-product --region eu-west-1 --product-arn arn:aws:securityhub:<region>::product/prowler/prowler
```

???+ note
    Specify the AWS region where you want to enable the integration. Ensure the region is correctly set within the ARN value. This command requires the`securityhub:securityhub:EnableImportFindingsForProduct` permission.

## Sending Findings to AWS Security Hub

Once AWS Security Hub is enabled, findings can be sent using the following commands:

For all regions:

```sh
prowler aws --security-hub
```

For a specific region (e.g., eu-west-1):

```sh
prowler --security-hub --region eu-west-1
```

???+ note
    It is recommended to send only fails to Security Hub and that is possible adding `--status FAIL` to the command. You can use, instead of the `--status FAIL` argument, the `--send-sh-only-fails` argument to save all the findings in the Prowler outputs but just to send FAIL findings to AWS Security Hub.

    Since Prowler perform checks to all regions by default you may need to filter by region when running Security Hub integration, as shown in the example above. Remember to enable Security Hub in the region or regions you need by calling `aws securityhub enable-security-hub --region <region>` and run Prowler with the option `-f/--region <region>` (if no region is used it will try to push findings in all regions hubs). Prowler will send findings to the Security Hub on the region where the scanned resource is located.

    To have updated findings in Security Hub you have to run Prowler periodically. Once a day or every certain amount of hours.

### Viewing Prowler Findings in AWS Security Hub

After enabling **AWS Security Hub**, findings from **Prowler** will be available in the configured AWS regions. Reviewing Prowler Findings in **AWS Security Hub**:

1. Enabling AWS Security Hub via Console

    Open the **AWS Security Hub** console: https://console.aws.amazon.com/securityhub/.

2. Select the “**Findings**” tab from the right-side menu bar. ![](./img/findings.png)

3. Use the search box filters and apply the “**Product Name**” filter with the value _Prowler_ to display findings sent by **Prowler**.

4. Click the check “**Title**” to access its detailed view, including its history and status. ![](./img/finding-details.png)

#### Compliance Information

As outlined in the Requirements section, the detailed view includes compliance details for each finding reported by **Prowler**.

## Sending Findings to Security Hub with IAM Role Assumption

### Multi-Account AWS Auditing

When auditing a multi-account AWS environment, Prowler allows you to send findings to a Security Hub in another account by assuming an IAM role from that target account.

#### Using an IAM Role to Send Findings

To send findings to Security Hub, use the `-R` flag in the Prowler command:

```sh
prowler --security-hub --role arn:aws:iam::123456789012:role/ProwlerExecutionRole
```

???+ note
    The specified IAM role must have the necessary permissions to send findings to Security Hub. For details on the required permissions, refer to the IAM policy: [prowler-security-hub.json](https://github.com/prowler-cloud/prowler/blob/master/permissions/prowler-security-hub.json)

## Sending Only Failed Findings to AWS Security Hub

When using **AWS Security Hub** integration, **Prowler** allows sending only failed findings (`FAIL`), helping reduce **AWS Security Hub** usage costs. To enable this, add the `--status FAIL` flag to the Prowler command:

```sh
prowler --security-hub --status FAIL
```

**Configuring Findings Output**

Instead of using `--status FAIL`, the `--send-sh-only-fails` argument to store all findings in Prowler outputs while sending only FAIL findings to AWS Security:

```sh
prowler --security-hub --send-sh-only-fails
```

## Skipping Updates for Findings in Security Hub

By default, Prowler archives any findings in Security Hub that were not detected in the latest scan. To prevent older findings from being archived, use the `--skip-sh-update` option:

```sh
prowler --security-hub --skip-sh-update
```
