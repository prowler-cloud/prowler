# AWS Security Hub Integration

Prowler supports natively and as **official integration** sending findings to [AWS Security Hub](https://aws.amazon.com/security-hub). This integration allows Prowler to import its findings to AWS Security Hub.

With Security Hub, you now have a single place that aggregates, organizes, and prioritizes your security alerts, or findings, from multiple AWS services, such as Amazon GuardDuty, Amazon Inspector, Amazon Macie, AWS Identity and Access Management (IAM) Access Analyzer, and AWS Firewall Manager, as well as from AWS Partner solutions and from Prowler for free.

Before sending findings to Prowler, you will need to perform next steps:

1. Since Security Hub is a region based service, enable it in the region or regions you require. Use the AWS Management Console or using the AWS CLI with this command if you have enough permissions:
    - `aws securityhub enable-security-hub --region <region>`.
2. Enable Prowler as partner integration integration. Use the AWS Management Console or using the AWS CLI with this command if you have enough permissions:
    - `aws securityhub enable-import-findings-for-product --region <region> --product-arn arn:aws:securityhub:<region>::product/prowler/prowler` (change region also inside the ARN).
    - Using the AWS Management Console:
     ![Screenshot 2020-10-29 at 10 26 02 PM](https://user-images.githubusercontent.com/3985464/97634660-5ade3400-1a36-11eb-9a92-4a45cc98c158.png)
3. Allow Prowler to import its findings to AWS Security Hub by adding the policy below to the role or user running Prowler:
    - [prowler-security-hub.json](https://github.com/prowler-cloud/prowler/blob/master/permissions/prowler-security-hub.json)

Once it is enabled, it is as simple as running the command below (for all regions):

```sh
prowler aws -S
```

or for only one filtered region like eu-west-1:

```sh
prowler -S -f eu-west-1
```

> **Note 1**: It is recommended to send only fails to Security Hub and that is possible adding `-q` to the command.

> **Note 2**: Since Prowler perform checks to all regions by defauls you may need to filter by region when runing Security Hub integration, as shown in the example above. Remember to enable Security Hub in the region or regions you need by calling `aws securityhub enable-security-hub --region <region>` and run Prowler with the option `-f <region>` (if no region is used it will try to push findings in all regions hubs).

> **Note 3** to have updated findings in Security Hub you have to run Prowler periodically. Once a day or every certain amount of hours.

Once you run findings for first time you will be able to see Prowler findings in Findings section:

![Screenshot 2020-10-29 at 10 29 05 PM](https://user-images.githubusercontent.com/3985464/97634676-66c9f600-1a36-11eb-9341-70feb06f6331.png)

## Skip sending updates of findings to Security Hub

By default, Prowler archives all its findings in Security Hub that have not appeared in the last scan.
You can skip this logic by using the option `--skip-sh-update` so Prowler will not archive older findings:

```sh
prowler -S --skip-sh-update
```
