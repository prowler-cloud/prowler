"use client";

import { useMountEffect } from "@/hooks/use-mount-effect";
import { isSampleId } from "@/lib/sample-preview/sample-records";
import { useLighthouseContextStore } from "@/store/lighthouse-context/store";
import type { LighthouseContextItem } from "@/types/lighthouse-context";

interface LighthouseContextContributorProps {
  contributorId: string;
  item: LighthouseContextItem;
}

export function LighthouseContextContributor({
  contributorId,
  item,
}: LighthouseContextContributorProps) {
  // Sample records exist only in the UI; Lighthouse would look them up in vain.
  if (isSampleId(item.id)) return null;

  return (
    <MountedLighthouseContextContributor
      key={`${contributorId}:${JSON.stringify(item)}`}
      contributorId={contributorId}
      item={item}
    />
  );
}

function MountedLighthouseContextContributor({
  contributorId,
  item,
}: LighthouseContextContributorProps) {
  const registerContribution = useLighthouseContextStore(
    (state) => state.registerContribution,
  );
  const removeContribution = useLighthouseContextStore(
    (state) => state.removeContribution,
  );

  // The wrapper keys this mounted registration by its bounded snapshot. New
  // server or interactive data therefore replaces stale context without a
  // direct dependency-driven useEffect.
  useMountEffect(() => {
    registerContribution(contributorId, item);
    return () => removeContribution(contributorId);
  });

  return null;
}
