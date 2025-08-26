# AWS Security Hub

Prowler can send the findings from your AWS account scans directly to AWS Security Hub. Once configured, you will see Prowler findings inside Security Hub for the AWS account scanned.

This integration is managed from the Integrations tab in Prowler.

![](../../img/integrations/aws-security-hub/integrations-tab.png)

## Requirements

- AWS Security Hub must be enabled in at least one AWS region for the AWS account associated with the credentials you provide.

- Prowler must be accepted as a partner integration in that region.

If no region is enabled for Security Hub, the integration in Prowler will not work.

## Enable AWS Security Hub

You can enable Security Hub either from the AWS Management Console or the AWS CLI. Since Security Hub is a regional service, you need to enable it in each region where you want to receive findings.

???+ warning
    Enabling Security Hub may incur costs. Refer to AWS Security Hub Pricing for details.

### Using the AWS Management Console

#### Enable AWS Security Hub

If you have currently AWS Security Hub enabled you can skip to the [next section](#enable-prowler-integration).

1. Open the **AWS Security Hub** console at [https://console.aws.amazon.com/securityhub/](https://console.aws.amazon.com/securityhub/).

2. When you open the Security Hub console for the first time make sure that you are in the region you want to enable, then choose **Go to Security Hub**.
![](../../img/integrations/aws-security-hub/enable.png)

3. On the next page, the Security standards section lists the security standards that Security Hub supports. Select the check box for a standard to enable it, and clear the check box to disable it.

4. Choose **Enable Security Hub**.
![](../../img/integrations/aws-security-hub/enable-2.png)

#### Enable Prowler Integration

If you have already configured **AWS Security Hub** for the **Prowler** Open Source scanner, you can skip to the [next section](#configure-integration).

Once **AWS Security Hub** is enabled you will need to enable **Prowler** as partner integration to allow Prowler to send findings to your **AWS Security Hub**.

1. Open the **AWS Security Hub** console at [https://console.aws.amazon.com/securityhub/](https://console.aws.amazon.com/securityhub/).

2. Select the **Integrations** tab in the right-side menu bar.
![](../../img/integrations/aws-security-hub/enable-partner-integration.png)

3. Search for **Prowler** in the text search box and the **Prowler** integration will appear.

4. Once there, click on **Accept Findings** to allow **AWS Security Hub** to receive findings from **Prowler**.
![](../../img/integrations/aws-security-hub/enable-partner-integration-2.png)

5. A new modal will appear to confirm that you are enabling the **Prowler** integration.
![](../../img/integrations/aws-security-hub/enable-partner-integration-3.png)

6. Right after click on **Accept Findings**, you will see that the integration is enabled in **AWS Security Hub**.
![](../../img/integrations/aws-security-hub/enable-partner-integration-4.png)

### Using the AWS CLI

To enable **AWS Security Hub** and the **Prowler** integration you have to run the following commands using the AWS CLI:

```shell
aws securityhub enable-security-hub --region <region>
```

???+ note
    For this command to work you will need the `securityhub:EnableSecurityHub` permission and set the AWS region where you want to enable AWS Security Hub.

Once **AWS Security Hub** is enabled you will need to enable **Prowler** as partner integration to allow Prowler to send findings to your AWS Security Hub. You have to run the following commands using the AWS CLI:

```shell
aws securityhub enable-import-findings-for-product --region eu-west-1 --product-arn arn:aws:securityhub:<region>::product/prowler/prowler
```

???+ note
    You will need to set the AWS region where you want to enable the integration and also the AWS region also within the ARN. For this command to work you will need the `securityhub:securityhub:EnableImportFindingsForProduct` permission.


## Configure Integration

The last steps to finish the configuration of the **AWS Security Hub** integration are the following:

1. In Prowler, go to the **Integrations** tab.
![](../../img/integrations/aws-security-hub/integrations-tab.png)

2. Click on the **AWS Security Hub** row and select the AWS account you want to enable the integration. Then, click on **Enable**.
![](../../img/integrations/aws-security-hub/enable-3.png)


4. If **AWS Security Hub** and the **Prowler** integration is configured in _at least_ one AWS region, the modal will allow you to enable the integration. Click on **Save** to enable it.
![](../../img/integrations/aws-security-hub/enable-5.png)


Next time your AWS account is scanned you will see the findings in **AWS Security Hub**.

???+ note
    You can check the next scan scheduled time just below of the  **AWS Security Hub** connection status under the **Connection** column.

### Send Failed Findings Only

When using the **AWS Security Hub** integration you can send only the `FAIL` findings generated by **Prowler**. Therefore, the **AWS Security Hub** usage costs eventually would be lower.

You can enable it selecting the **Send Failed Findings Only** checkbox when configuring or editing the integration.
![](../../img/integrations/aws-security-hub/enable-6.png)


## Check Integration

- Security Hub automatically detects new regions where the integration is enabled.

- In Prowler, use the Test Connection button in the Integrations tab to see which regions are active for the integration.

## Delete Integration

To delete the AWS Security Hub integration go to the **Integrations** tab, click in the **AWS Security Hub** row and then click on the **Delete** button.

![](../../img/integrations/aws-security-hub/delete-integration.png)

A modal will appear to confirm the deletion of the integration. Just click on the **Remove** button to delete the integration.

![](../../img/integrations/aws-security-hub/delete-integration-modal.png)

## See you Prowler findings in AWS Security Hub

Once configured the **AWS Security Hub** in your next scan you will receive the **Prowler** findings in the AWS regions configured. To review those findings in **AWS Security Hub**:

1. Open the **AWS Security Hub** console at [https://console.aws.amazon.com/securityhub/](https://console.aws.amazon.com/securityhub/).

2. Select the **Findings** tab in the right-side menu bar.
![](../../img/integrations/aws-security-hub/findings.png)

3. Use the search box filters and use the **Product Name** filter with the value **Prowler** to see the findings sent from **Prowler**.

4. Then, you can click on the check **Title** to see the details and the history of a finding.
![](../../img/integrations/aws-security-hub/finding-details.png)

As you can see in the related requirements section, in the detailed view of the findings, **Prowler** also sends compliance information related to every finding.
