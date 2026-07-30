"use client";

import { useEffect, useRef, useState } from "react";

import {
  createOrganization,
  createOrganizationSecret,
  getDiscovery,
  listOrganizationsByExternalId,
  listOrganizationSecretsByOrganizationId,
  triggerDiscovery,
  updateOrganizationSecret,
} from "@/actions/organizations/organizations";
import { useOrgSetupStore } from "@/store/organizations/store";
import { DISCOVERY_STATUS } from "@/types/organizations";

import { extractErrorMessage } from "./error-utils";
import {
  getOrgSetupStrategy,
  OrgSetupStrategy,
  OrgSetupSubmissionData,
} from "./org-setup-strategy";

const DISCOVERY_POLL_INTERVAL_MS = 3000;
const DISCOVERY_MAX_RETRIES = 60;

/**
 * Used once discovery has already come back successfully: from that point the
 * credentials are proven good, so a later failure must not send the user off to
 * re-check them.
 */
const UNEXPECTED_DISCOVERY_RESULT =
  "The organization was authenticated, but its discovery result could not be read. Please try again.";

function sleepWithAbort(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) {
      resolve();
      return;
    }

    const timeoutId = window.setTimeout(resolve, ms);
    signal.addEventListener(
      "abort",
      () => {
        window.clearTimeout(timeoutId);
        resolve();
      },
      { once: true },
    );
  });
}

interface UseOrgSetupSubmissionProps {
  stackSetExternalId: string;
  onNext: () => void;
  setFieldError: (
    field: "awsOrgId" | "organizationName",
    message: string,
  ) => void;
}

interface ServerErrorResult {
  error?: string;
  errors?: Array<{ detail: string; source?: { pointer: string } }>;
}

export function useOrgSetupSubmission({
  stackSetExternalId,
  onNext,
  setFieldError,
}: UseOrgSetupSubmissionProps) {
  const [apiError, setApiError] = useState<string | null>(null);
  const isMountedRef = useRef(true);
  const discoveryAbortControllerRef = useRef<AbortController | null>(null);
  const {
    setOrganization,
    setDiscoveryTriggered,
    setDiscovery,
    setSelectedCandidateIds,
    clearValidationState,
  } = useOrgSetupStore();

  useEffect(() => {
    isMountedRef.current = true;

    return () => {
      isMountedRef.current = false;
      discoveryAbortControllerRef.current?.abort();
    };
  }, []);

  const handleServerError = (result: ServerErrorResult, context: string) => {
    if (!isMountedRef.current) {
      return;
    }

    if (result.errors?.length) {
      for (const err of result.errors) {
        const pointer = err.source?.pointer ?? "";

        if (pointer.includes("external_id") && context === "Organization") {
          setFieldError("awsOrgId", err.detail);
          setApiError(err.detail);
        } else if (pointer.includes("name")) {
          setFieldError("organizationName", err.detail);
        } else {
          setApiError(err.detail);
        }
      }
    } else {
      setApiError(extractErrorMessage(result, `Failed to create ${context}`));
    }
  };

  const pollDiscoveryResult = async (
    organizationId: string,
    discoveryId: string,
    signal: AbortSignal,
    strategy: OrgSetupStrategy,
  ): Promise<unknown | null> => {
    for (let attempt = 0; attempt < DISCOVERY_MAX_RETRIES; attempt += 1) {
      if (signal.aborted || !isMountedRef.current) {
        return null;
      }

      const result = await getDiscovery(organizationId, discoveryId);
      if (signal.aborted || !isMountedRef.current) {
        return null;
      }

      if (result?.error) {
        setApiError(strategy.authFailureMessage(result.error));
        return null;
      }

      const status = result?.data?.attributes?.status;

      if (!status) {
        setApiError(UNEXPECTED_DISCOVERY_RESULT);
        return null;
      }

      if (status === DISCOVERY_STATUS.SUCCEEDED) {
        return result.data.attributes.result;
      }

      if (status === DISCOVERY_STATUS.FAILED) {
        const backendError = result.data.attributes.error;
        setApiError(
          backendError
            ? strategy.authFailureMessage(backendError)
            : strategy.authFailureMessage(),
        );
        return null;
      }

      await sleepWithAbort(DISCOVERY_POLL_INTERVAL_MS, signal);
    }

    if (signal.aborted || !isMountedRef.current) {
      return null;
    }

    setApiError(strategy.timeoutMessage);
    return null;
  };

  const submitOrganizationSetup = async (data: OrgSetupSubmissionData) => {
    // The form's own tag picks the strategy, so the collected fields and the
    // credentials/discovery built from them always belong to the same type.
    const strategy = getOrgSetupStrategy(data.orgType);
    discoveryAbortControllerRef.current?.abort();
    const abortController = new AbortController();
    discoveryAbortControllerRef.current = abortController;
    const isCancelled = () =>
      !isMountedRef.current || abortController.signal.aborted;
    const setApiErrorIfActive = (message: string) => {
      if (!isCancelled()) {
        setApiError(message);
      }
    };

    let hasDiscovered = false;

    try {
      if (!isCancelled()) {
        setApiError(null);
      }
      clearValidationState();

      const externalId = strategy.getExternalId(data);
      const resolvedOrganizationName = strategy.getResolvedName(data);

      const existingOrganizationsResult = await listOrganizationsByExternalId(
        externalId,
        strategy.orgType,
      );
      if (isCancelled()) {
        return;
      }

      if (existingOrganizationsResult?.error) {
        setApiErrorIfActive(existingOrganizationsResult.error);
        return;
      }

      const existingOrganization = Array.isArray(
        existingOrganizationsResult?.data,
      )
        ? existingOrganizationsResult.data.find(
            (organization: {
              id: string;
              attributes?: { external_id?: string; org_type?: string };
            }) =>
              organization?.attributes?.external_id === externalId &&
              organization?.attributes?.org_type === strategy.orgType,
          )
        : null;

      let orgId = existingOrganization?.id as string | undefined;

      if (!orgId) {
        const orgFormData = new FormData();
        orgFormData.set("name", resolvedOrganizationName);
        orgFormData.set("externalId", externalId);
        orgFormData.set("orgType", strategy.orgType);

        const orgResult = await createOrganization(orgFormData);
        if (isCancelled()) {
          return;
        }

        if (orgResult?.error || orgResult?.errors?.length) {
          handleServerError(orgResult, "Organization");
          return;
        }

        orgId = orgResult.data.id;
      }

      if (!orgId) {
        setApiErrorIfActive(
          "Unable to resolve organization ID for authentication.",
        );
        return;
      }

      const organizationNameForStore =
        existingOrganization?.attributes?.name ?? resolvedOrganizationName;
      setOrganization(orgId, organizationNameForStore, externalId);

      const existingSecretsResult =
        await listOrganizationSecretsByOrganizationId(orgId);
      if (isCancelled()) {
        return;
      }

      if (existingSecretsResult?.error) {
        setApiErrorIfActive(existingSecretsResult.error);
        return;
      }

      const existingSecretId =
        Array.isArray(existingSecretsResult?.data) &&
        existingSecretsResult.data.length > 0
          ? (existingSecretsResult.data[0]?.id as string | undefined)
          : undefined;

      const secretPayload = strategy.buildSecretPayload(
        data,
        stackSetExternalId,
      );

      const secretResult = existingSecretId
        ? await updateOrganizationSecret(existingSecretId, secretPayload)
        : await createOrganizationSecret(orgId, secretPayload);
      if (isCancelled()) {
        return;
      }

      if (secretResult?.error) {
        handleServerError(secretResult, "Secret");
        return;
      }

      const discoveryResult = await triggerDiscovery(orgId);
      if (isCancelled()) {
        return;
      }

      if (discoveryResult?.error) {
        setApiErrorIfActive(discoveryResult.error);
        return;
      }

      const discoveryId = discoveryResult.data.id;
      // Persist the discovery id at trigger time so an interrupted discovery
      // can be resumed on wizard re-entry.
      setDiscoveryTriggered(discoveryId);

      const resolvedDiscoveryResult = await pollDiscoveryResult(
        orgId,
        discoveryId,
        abortController.signal,
        strategy,
      );

      if (!resolvedDiscoveryResult || isCancelled()) {
        return;
      }

      hasDiscovered = true;

      const { hierarchy, defaultSelection } = strategy.ingestDiscovery(
        resolvedDiscoveryResult,
        data,
      );
      setDiscovery(discoveryId, hierarchy);
      setSelectedCandidateIds(defaultSelection);
      onNext();
    } catch {
      if (!isCancelled()) {
        // Ingesting the result is the only work left once `hasDiscovered` is set,
        // and a malformed result is not a credentials problem.
        setApiError(
          hasDiscovered
            ? UNEXPECTED_DISCOVERY_RESULT
            : strategy.authFailureMessage(),
        );
      }
    } finally {
      if (discoveryAbortControllerRef.current === abortController) {
        discoveryAbortControllerRef.current = null;
      }
    }
  };

  return {
    apiError,
    setApiError,
    submitOrganizationSetup,
  };
}
