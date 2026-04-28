"use client";

import { EffectCallback, useEffect } from "react";

/**
 * Runs an effect exactly once on component mount.
 * Project-approved wrapper — use this instead of useEffect(..., []).
 */
export function useMountEffect(effect: EffectCallback) {
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(effect, []);
}
