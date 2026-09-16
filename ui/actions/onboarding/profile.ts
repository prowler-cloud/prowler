"use server";

import { z } from "zod";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";
import {
  DECLARED_CLOUD_ACCOUNTS,
  DECLARED_ROLE,
  DECLARED_SENIORITY,
  DECLARED_TEAM_SIZE,
  type OnboardingProfileAnswers,
} from "@/types/onboarding-profile";

const ONBOARDING_PROFILES_PATH = "/onboarding-profiles";
const RESOURCE_TYPE = "onboarding-profiles";

// Explicit outcome instead of the raw API payload: the caller records the
// step as resolved only when the row was really written, and a transport
// failure is as unsuccessful as a rejected payload.
export interface OnboardingProfileResult {
  stored: boolean;
  error?: string;
}

const onboardingProfileAnswersSchema = z.object({
  declared_cloud_accounts: z.enum(
    Object.values(DECLARED_CLOUD_ACCOUNTS) as [string, ...string[]],
  ),
  declared_team_size: z.enum(
    Object.values(DECLARED_TEAM_SIZE) as [string, ...string[]],
  ),
  declared_role: z.enum(Object.values(DECLARED_ROLE) as [string, ...string[]]),
  declared_seniority: z.enum(
    Object.values(DECLARED_SENIORITY) as [string, ...string[]],
  ),
});

const GENERIC_FAILURE = "The onboarding profile could not be saved.";

const failureMessage = (payload: unknown): string | undefined => {
  if (typeof payload !== "object" || payload === null) return undefined;
  const result = payload as { error?: unknown; errors?: unknown };
  if (Array.isArray(result.errors)) {
    const detail = (result.errors[0] as { detail?: unknown })?.detail;
    if (typeof detail === "string") return detail;
  }
  return typeof result.error === "string" ? result.error : undefined;
};

const postOnboardingProfile = async (
  attributes: Record<string, unknown>,
): Promise<OnboardingProfileResult> => {
  const body = JSON.stringify({
    data: { type: RESOURCE_TYPE, attributes },
  });

  let response: Response;
  try {
    // Inside the boundary: `getAuthHeaders` awaits `auth()`, which rejects on
    // an undecodable session. The contract above promises a result, not a
    // throw, so a dead session must read as "not stored" and leave the step
    // eligible for the next login.
    const headers = await getAuthHeaders({ contentType: true });
    response = await fetch(`${apiBaseUrl}${ONBOARDING_PROFILES_PATH}`, {
      method: "POST",
      headers,
      body,
    });
  } catch (error) {
    handleApiError(error);
    return { stored: false, error: GENERIC_FAILURE };
  }

  // `handleApiResponse` reports to Sentry and throws on server errors; the
  // status is what decides the outcome, since a rejection can come back
  // without an `errors` array.
  try {
    const payload = await handleApiResponse(response);
    if (!response.ok) {
      return {
        stored: false,
        error: failureMessage(payload) ?? GENERIC_FAILURE,
      };
    }
    return { stored: true };
  } catch (error) {
    handleApiError(error);
    return { stored: false, error: GENERIC_FAILURE };
  }
};

// Records the four declared buckets. The API keeps the first answer per
// tenant: a repeated submission answers 200 with the stored profile.
export const submitOnboardingProfile = async (
  answers: OnboardingProfileAnswers,
): Promise<OnboardingProfileResult> =>
  postOnboardingProfile(onboardingProfileAnswersSchema.parse(answers));

// A skip is a fact worth storing: it separates "declined" from "never
// shown" in the funnel.
export const skipOnboardingProfile =
  async (): Promise<OnboardingProfileResult> =>
    postOnboardingProfile({ skipped: true });

// Whether the tenant already went through the step on any device. `undefined`
// means the read failed; the gate fails open and does not force the modal.
export const isOnboardingProfileRecorded = async (): Promise<
  boolean | undefined
> => {
  const url = new URL(`${apiBaseUrl}${ONBOARDING_PROFILES_PATH}`);
  url.searchParams.set("page[size]", "1");

  try {
    const headers = await getAuthHeaders({ contentType: false });
    const response = await fetch(url.toString(), { headers });
    if (!response.ok) return undefined;
    const payload = await response.json();
    return Array.isArray(payload?.data) ? payload.data.length > 0 : undefined;
  } catch {
    return undefined;
  }
};
