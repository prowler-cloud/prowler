"use client";

import { LockKeyhole } from "lucide-react";
import { type ReactNode, useState } from "react";

import { Alert, AlertDescription } from "@/components/shadcn";
import { PremiumBadge } from "@/components/shared/premium-badge";
import { useMountEffect } from "@/hooks/use-mount-effect";
import {
  CLOUD_UPGRADE_SURFACE,
  type CloudUpgradeFeature,
} from "@/types/cloud-upgrade";

import { dismissPremiumNudge, isPremiumNudgeDismissed } from "./premium-nudge";

interface PremiumNudgeBannerProps {
  nudgeId: string;
  feature: CloudUpgradeFeature;
  children: ReactNode;
}

export function PremiumNudgeBanner({
  nudgeId,
  feature,
  children,
}: PremiumNudgeBannerProps) {
  const [isVisible, setIsVisible] = useState(false);

  useMountEffect(() => {
    try {
      setIsVisible(!isPremiumNudgeDismissed(nudgeId, localStorage));
    } catch {
      setIsVisible(true);
    }
  });

  if (!isVisible) return null;

  const handleClose = () => {
    try {
      dismissPremiumNudge(nudgeId, localStorage);
    } catch {}
    setIsVisible(false);
  };

  return (
    <Alert
      variant="info"
      role="note"
      onClose={handleClose}
      closeLabel="Dismiss"
      className="animate-fade-in"
    >
      <LockKeyhole />
      <AlertDescription>
        <p>{children}</p>
        <PremiumBadge
          feature={feature}
          surface={CLOUD_UPGRADE_SURFACE.NUDGE}
          compact
        />
      </AlertDescription>
    </Alert>
  );
}
