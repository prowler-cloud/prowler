import "server-only";

import { fetchCurrentUser } from "@/lib/auth/current-user";
import { readBoolEnv } from "@/lib/runtime-env";

import {
  isRegistryEligible,
  REGISTRY_ACCESS,
  type RegistryAccessResult,
} from "./access";

const CURRENT_USER_TIMEOUT_MS = 5_000;

const hasEnabledProcessFlags = () =>
  readBoolEnv("UI_CLOUD_ENABLED") && readBoolEnv("UI_REGISTRY_ENABLED");

export async function evaluateRegistryAccess(
  accessToken?: string | null,
): Promise<RegistryAccessResult> {
  if (!hasEnabledProcessFlags() || !accessToken?.trim()) {
    return { status: REGISTRY_ACCESS.INELIGIBLE };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), CURRENT_USER_TIMEOUT_MS);

  try {
    const currentUser = await fetchCurrentUser(accessToken, {
      signal: controller.signal,
    });
    if (currentUser.manageRegistry === undefined) {
      return { status: REGISTRY_ACCESS.UNKNOWN };
    }
    return {
      status: isRegistryEligible(true, true, currentUser.manageRegistry)
        ? REGISTRY_ACCESS.ELIGIBLE
        : REGISTRY_ACCESS.INELIGIBLE,
    };
  } catch {
    return { status: REGISTRY_ACCESS.UNKNOWN };
  } finally {
    clearTimeout(timeout);
  }
}
