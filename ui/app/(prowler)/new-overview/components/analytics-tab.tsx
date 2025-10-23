"use client";

import {
  BaseCard,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/shadcn";

interface AnalyticsTabProps {
  isActive: boolean;
  failFindingsData: {
    total: number;
    new: number;
    muted: number;
  };
  passFindingsData: {
    total: number;
    new: number;
    muted: number;
  };
}

export function AnalyticsTab({
  failFindingsData,
  passFindingsData,
}: AnalyticsTabProps) {
  const totalFindings = failFindingsData.total + passFindingsData.total;
  const failPercentage = Math.round(
    (failFindingsData.total / totalFindings) * 100,
  );
  const passPercentage = Math.round(
    (passFindingsData.total / totalFindings) * 100,
  );

  return (
    <BaseCard>
      <CardHeader>
        <CardTitle>Analytics Summary</CardTitle>
      </CardHeader>

      <CardContent className="space-y-6">
        <div className="grid grid-cols-2 gap-4">
          {/* Fail Findings Stats */}
          <div className="rounded-lg border border-slate-700 bg-slate-800 p-4">
            <div className="mb-2 text-xs font-medium text-slate-400">
              Failed Findings
            </div>
            <div className="mb-3 text-2xl font-bold text-rose-400">
              {failFindingsData.total}
            </div>
            <div className="space-y-1 text-xs text-slate-400">
              <div>New: {failFindingsData.new}</div>
              <div>Muted: {failFindingsData.muted}</div>
              <div>Percentage: {failPercentage}%</div>
            </div>
          </div>

          {/* Pass Findings Stats */}
          <div className="rounded-lg border border-slate-700 bg-slate-800 p-4">
            <div className="mb-2 text-xs font-medium text-slate-400">
              Passed Findings
            </div>
            <div className="mb-3 text-2xl font-bold text-green-400">
              {passFindingsData.total}
            </div>
            <div className="space-y-1 text-xs text-slate-400">
              <div>New: {passFindingsData.new}</div>
              <div>Muted: {passFindingsData.muted}</div>
              <div>Percentage: {passPercentage}%</div>
            </div>
          </div>
        </div>

        {/* Summary */}
        <div className="rounded-lg border border-slate-700 bg-slate-800 p-4">
          <div className="mb-3 text-xs font-medium text-slate-400">
            Total Summary
          </div>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-slate-400">Total Findings:</span>
              <span className="font-semibold text-white">{totalFindings}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">New Findings:</span>
              <span className="font-semibold text-white">
                {failFindingsData.new + passFindingsData.new}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Total Muted:</span>
              <span className="font-semibold text-white">
                {failFindingsData.muted + passFindingsData.muted}
              </span>
            </div>
          </div>
        </div>
      </CardContent>
    </BaseCard>
  );
}
