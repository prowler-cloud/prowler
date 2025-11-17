import { Card, CardBody } from "@heroui/card";
import { Spacer } from "@heroui/spacer";
import { Suspense } from "react";

import { getAttackPathScans } from "@/actions/attack-paths";
import {
  AWSConnectionWarning,
  ScanListTable,
} from "@/components/attack-paths/scan-selection";

/**
 * Step 1: Attack Path Scan Selection
 * Displays list of AWS accounts with their latest attack path scans
 */
export default async function SelectScanPage() {
  const scansData = await getAttackPathScans();

  const hasScans = scansData?.data && scansData.data.length > 0;
  const hasError = scansData === undefined;

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h2 className="dark:text-prowler-theme-pale/90 text-xl font-semibold">
          Select Attack Path Scan
        </h2>
        <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
          Choose an AWS account and its latest attack path scan to analyze.
        </p>
      </div>

      <Spacer y={4} />

      {hasError ? (
        <AWSConnectionWarning />
      ) : !hasScans ? (
        <Card className="bg-blue-50 dark:bg-blue-950/20">
          <CardBody className="gap-2">
            <p className="font-medium text-blue-900 dark:text-blue-100">
              No Attack Path Scans Available
            </p>
            <p className="text-sm text-blue-800 dark:text-blue-200">
              AWS is connected, but no attack path scans have been generated
              yet. Attack path scans are created automatically after each
              Prowler scan completes. Please run a Prowler scan on your AWS
              provider first.
            </p>
          </CardBody>
        </Card>
      ) : (
        <Suspense fallback={<div>Loading scans...</div>}>
          <ScanListTable scans={scansData!.data} />
        </Suspense>
      )}
    </div>
  );
}
