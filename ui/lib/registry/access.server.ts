import "server-only";

import { fetchCurrentUser } from "@/lib/auth/current-user";
import { readEnv } from "@/lib/runtime-env";

import {
  isRegistryEligible,
  REGISTRY_ACCESS,
  registryAccessResult,
  type RegistryAccessResult,
} from "./access";

const CURRENT_USER_TIMEOUT_MS = 5_000;

const hasEnabledProcessFlags = () =>
  readEnv("UI_CLOUD_ENABLED") === "true" &&
  readEnv("UI_REGISTRY_ENABLED") === "true";

export async function evaluateRegistryAccess(
  accessToken?: string | null,
): Promise<RegistryAccessResult> {
  if (!hasEnabledProcessFlags() || !accessToken?.trim()) {
    return registryAccessResult(REGISTRY_ACCESS.INELIGIBLE);
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), CURRENT_USER_TIMEOUT_MS);

  try {
    const currentUser = await fetchCurrentUser(accessToken, {
      signal: controller.signal,
    });
    if (currentUser.manageRegistry === undefined) {
      return registryAccessResult(REGISTRY_ACCESS.UNKNOWN);
    }
    return registryAccessResult(
      isRegistryEligible(true, true, currentUser.manageRegistry)
        ? REGISTRY_ACCESS.ELIGIBLE
        : REGISTRY_ACCESS.INELIGIBLE,
    );
  } catch {
    return registryAccessResult(REGISTRY_ACCESS.UNKNOWN);
  } finally {
    clearTimeout(timeout);
  }
}
