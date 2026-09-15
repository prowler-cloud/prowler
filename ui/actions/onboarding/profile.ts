"use server";

import { z } from "zod";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";
import {
  DECLARED_CLOUD_ACCOUNTS,
  DECLARED_ROLE,
  DECLARED_TEAM_SIZE,
  type OnboardingProfileAnswers,
} from "@/types/onboarding-profile";

const ONBOARDING_PROFILES_PATH = "/onboarding-profiles";
const RESOURCE_TYPE = "onboarding-profiles";

const onboardingProfileAnswersSchema = z.object({
  declared_cloud_accounts: z.enum(
    Object.values(DECLARED_CLOUD_ACCOUNTS) as [string, ...string[]],
  ),
  declared_team_size: z.enum(
    Object.values(DECLARED_TEAM_SIZE) as [string, ...string[]],
  ),
  declared_role: z.enum(Object.values(DECLARED_ROLE) as [string, ...string[]]),
});

const postOnboardingProfile = async (attributes: Record<string, unknown>) => {
  const headers = await getAuthHeaders({ contentType: true });
  const body = JSON.stringify({
    data: { type: RESOURCE_TYPE, attributes },
  });

  try {
    const response = await fetch(`${apiBaseUrl}${ONBOARDING_PROFILES_PATH}`, {
      method: "POST",
      headers,
      body,
    });
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

// Records the three declared buckets. The API keeps the first answer per
// tenant: a repeated submission answers 200 with the stored profile.
export const submitOnboardingProfile = async (
  answers: OnboardingProfileAnswers,
) => postOnboardingProfile(onboardingProfileAnswersSchema.parse(answers));

// A skip is a fact worth storing: it separates "declined" from "never
// shown" in the funnel.
export const skipOnboardingProfile = async () =>
  postOnboardingProfile({ skipped: true });

// Whether the tenant already went through the step on any device. `undefined`
// means the read failed; the gate fails open and does not force the modal.
export const isOnboardingProfileRecorded = async (): Promise<
  boolean | undefined
> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${ONBOARDING_PROFILES_PATH}`);
  url.searchParams.set("page[size]", "1");

  try {
    const response = await fetch(url.toString(), { headers });
    if (!response.ok) return undefined;
    const payload = await response.json();
    return Array.isArray(payload?.data) ? payload.data.length > 0 : undefined;
  } catch {
    return undefined;
  }
};
