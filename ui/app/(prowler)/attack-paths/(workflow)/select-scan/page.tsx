import { Suspense } from "react";

import { getAttackPathScans } from "@/actions/attack-paths";
import { Card, CardContent } from "@/components/shadcn";

import { AWSConnectionWarning, ScanListTable } from "./_components";

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

      {hasError ? (
        <AWSConnectionWarning />
      ) : !hasScans ? (
        <Card className="bg-bg-info-secondary dark:bg-bg-info-secondary/20">
          <CardContent className="gap-4 pt-6">
            <p className="text-text-info dark:text-text-info font-medium">
              No Attack Path Scans Available
            </p>
            <p className="text-text-info dark:text-text-info/80 text-sm">
              AWS is connected, but no attack path scans have been generated
              yet. Attack path scans are created automatically after each
              Prowler scan completes. Please run a Prowler scan on your AWS
              provider first.
            </p>
          </CardContent>
        </Card>
      ) : (
        <Suspense fallback={<div>Loading scans...</div>}>
          <ScanListTable scans={scansData!.data} />
        </Suspense>
      )}
    </div>
  );
}
