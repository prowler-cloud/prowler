"use client";

import { ActionsList } from "@/components/realtime/actions-list";
import { DetectionsList } from "@/components/realtime/detections-list";

export function RemediationTab({
  providerId,
  canManage,
  demo = false,
}: {
  providerId: string;
  canManage: boolean;
  demo?: boolean;
}) {
  return (
    <div className="flex flex-col gap-8">
      <ActionsList providerId={providerId} canManage={canManage} demo={demo} />
      <DetectionsList providerId={providerId} demo={demo} />
    </div>
  );
}
