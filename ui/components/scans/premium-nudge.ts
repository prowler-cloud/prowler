const PREMIUM_NUDGE_STORAGE_PREFIX = "prowler:premium-nudge-dismissed:";
export const PREMIUM_NUDGE_COOLDOWN_MS = 14 * 24 * 60 * 60 * 1000;

const storageKey = (nudgeId: string) =>
  `${PREMIUM_NUDGE_STORAGE_PREFIX}${nudgeId}`;

export function isPremiumNudgeDismissed(
  nudgeId: string,
  storage: Pick<Storage, "getItem">,
  now = Date.now(),
): boolean {
  const dismissedAt = Number(storage.getItem(storageKey(nudgeId)));
  return Number.isFinite(dismissedAt) && dismissedAt > 0
    ? now - dismissedAt < PREMIUM_NUDGE_COOLDOWN_MS
    : false;
}

export function dismissPremiumNudge(
  nudgeId: string,
  storage: Pick<Storage, "setItem">,
  now = Date.now(),
) {
  storage.setItem(storageKey(nudgeId), String(now));
}
