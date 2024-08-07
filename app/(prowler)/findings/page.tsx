import { Spacer } from "@nextui-org/react";
import React, { Suspense } from "react";

import {
  ColumnsFindings,
  DataTableFindings,
  SkeletonTableFindings,
} from "@/components/findings";
import { Header } from "@/components/ui";

export default async function Findings() {
  return (
    <>
      <Header title="Findings" icon="ph:list-checks-duotone" />
      <Spacer />
      <div className="flex flex-col items-start w-full overflow-hidden">
        <Spacer y={6} />
        <Suspense fallback={<SkeletonTableFindings />}>
          <SSRDataTable />
        </Suspense>
      </div>
    </>
  );
}

const SSRDataTable = async () => {
  return (
    <DataTableFindings
      columns={ColumnsFindings}
      data={[
        {
          id: "12345",
          attributes: {
            CheckTitle:
              "Ensure users of groups with AdministratorAccess policy have MFA tokens enabled",
            severity: "high",
            status: "fail",
            region: "us-west-2",
            service: "cloudformation",
            account: "dev (106908755756)",
          },
          card: {
            resourceId:
              "StackSet-AWSControlTowerBP-BASELINE-CLOUDWATCH-57c2a54c-9a36-4af9-a910-d1adb424c62a",
            resourceLink:
              "https://app.prowler.pro/app/findings?date=2024-08-05&search=StackSet-AWSControlTowerBP-BASELINE-CLOUDWATCH-57c2a54c-9a36-4af9-a910-d1adb424c62a",
            resourceARN:
              "arn:aws:cloudformation:eu-west-1:714274078102:stack/StackSet-AWSControlTowerBP-BASELINE-CLOUDWATCH-57c2a54c-9a36-4af9-a910-d1adb424c62a/9656eda0-909c-11ec-8fb2-06f4f86422d5",
            checkId: "cloudformation_stack_outputs_find_secrets",
            checkLink:
              "https://app.prowler.pro/app/findings?date=2024-08-05&search=cloudformation_stack_outputs_find_secrets",
            type: "Not applicable",
            scanTime: "2024-08-05 @ 14:22:00 UTC",
            findingId: "ba123291-03a5-49a1-b962-6fdb1d2b9c9b",
            findingLink:
              "https://app.prowler.pro/app/findings?date=2024-08-05&search=ba123291-03a5-49a1-b962-6fdb1d2b9c9b",
            details:
              "Potential secret found in Stack StackSet-AWSControlTowerBP-BASELINE-CLOUDWATCH-57c2a54c-9a36-4af9-a910-d1adb424c62a Outputs.",
            riskLink:
              "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/outputs-section-structure.html",
            riskDetails:
              "Secrets hardcoded into CloudFormation outputs can be used by malware and bad actors to gain lateral access to other services.",
            recommendationLink:
              "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-secret-generatesecretstring.html",
            recommendationDetails:
              "Implement automated detective control to scan accounts for passwords and secrets. Use secrets manager service to store and retrieve passwords and secrets.",
            referenceInformation: "CLI",
            referenceLink:
              "https://docs.prowler.com/checks/aws/secrets-policies/bc_aws_secrets_2/#cli-command",
          },
        },
        {
          id: "67891",
          attributes: {
            CheckTitle: "Find secrets in CloudFormation outputs",
            severity: "low",
            status: "success",
            region: "us-east-1",
            service: "cloudformation",
            account: "stg (987654321987)",
          },
          card: {
            resourceId: "<root_account>",
            resourceLink:
              "https://app.prowler.pro/app/findings?search=%3Croot_account%3E",
            resourceARN: "arn:aws:iam::714274078102:root",
            checkId: "iam_root_mfa_enabled",
            checkLink:
              "https://app.prowler.pro/app/findings?search=iam_root_mfa_enabled",
            type: "Software and Configuration Checks, Industry and Regulatory Standards, CIS AWS Foundations Benchmark",
            scanTime: "2024-08-05 @ 14:22:00 UTC",
            findingId: "bc3a34e0-16f0-4ea1-ac62-f796c8af3448",
            findingLink:
              "https://app.prowler.pro/app/findings?date=2024-08-05&search=bc3a34e0-16f0-4ea1-ac62-f796c8af3448",
            details: "MFA is not enabled for root account.",
            riskLink: "",
            riskDetails:
              "The root account is the most privileged user in an AWS account. MFA adds an extra layer of protection on top of a user name and password. With MFA enabled when a user signs in to an AWS website they will be prompted for their user name and password as well as for an authentication code from their AWS MFA device. When virtual MFA is used for root accounts it is recommended that the device used is NOT a personal device but rather a dedicated mobile device (tablet or phone) that is managed to be kept charged and secured independent of any individual personal devices. (non-personal virtual MFA) This lessens the risks of losing access to the MFA due to device loss / trade-in or if the individual owning the device is no longer employed at the company.",
            recommendationLink:
              "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_mfa",
            recommendationDetails:
              "Using IAM console navigate to Dashboard and expand Activate MFA on your root account.",
            referenceInformation: "",
            referenceLink: "",
          },
        },
      ]}
    />
  );
};
