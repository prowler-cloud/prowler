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

import {
  apiErrorFieldNames,
  ApiErrorObject,
  describeApiError,
  extractErrorMessage,
} from "./error-utils";
import {
  bindOrgSetupStrategy,
  BoundOrgSetupStrategy,
  OrgSetupErrorField,
  OrgSetupSubmissionData,
} from "./org-setup-strategy";

const DISCOVERY_POLL_INTERVAL_MS = 3000;
const DISCOVERY_MAX_RETRIES = 60;

/**
 * Used once the credentials have already been accepted: from that point they are
 * proven good, so a response we cannot read must not send the user off to
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
  setFieldError: (field: OrgSetupErrorField, message: string) => boolean;
}

interface ServerErrorResult {
  error?: string;
  errors?: ApiErrorObject[];
}

type PollOutcome =
  | { kind: "resolved"; result: unknown }
  | { kind: "failed" } // apiError already set
  | { kind: "cancelled" }
  | { kind: "timeout" };

interface SubmitOptions {
  /** Skip the existing-secret replacement confirmation (user already agreed). */
  confirmReplace?: boolean;
}

function getOrganizationProviderCount(organization: unknown): number {
  const providers = (
    organization as {
      relationships?: { providers?: { data?: unknown[] } };
    } | null
  )?.relationships?.providers?.data;
  return Array.isArray(providers) ? providers.length : 0;
}

export function useOrgSetupSubmission({
  stackSetExternalId,
  onNext,
  setFieldError,
}: UseOrgSetupSubmissionProps) {
  const [apiError, setApiError] = useState<string | null>(null);
  // Set when submission finds an existing organization secret that a
  // replacement would overwrite; the form confirms before proceeding.
  const [replaceSecretWarning, setReplaceSecretWarning] = useState<{
    providerCount: number;
  } | null>(null);
  // Set when discovery polling exhausts its client-side budget while the worker
  // is still running; the form offers *keep waiting* (resume) vs *retry* (new).
  const [discoveryTimedOut, setDiscoveryTimedOut] = useState(false);
  // Set when discovery completes with a failed status; the sanitized error is in
  // apiError and the form offers a retry (a fresh discovery).
  const [discoveryFailed, setDiscoveryFailed] = useState(false);
  // True whenever the setup chain is running.
  const [isSubmissionPending, setIsSubmissionPending] = useState(false);
  const isMountedRef = useRef(true);
  const pendingSubmitDataRef = useRef<OrgSetupSubmissionData | null>(null);
  // Enough context to resume polling the same discovery (keep waiting) or
  // trigger a fresh one (retry) after a client-side timeout. The strategy
  // carries its submission data, so resuming cannot re-pair the two.
  const resumeContextRef = useRef<{
    orgId: string;
    discoveryId: string;
    strategy: BoundOrgSetupStrategy;
  } | null>(null);
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

  const handleServerError = (
    result: ServerErrorResult,
    context: string,
    strategy: BoundOrgSetupStrategy,
  ) => {
    if (!isMountedRef.current) {
      return;
    }

    if (result.errors?.length) {
      for (const err of result.errors) {
        // Both halves tolerate a `detail`-less error: the field can be named by
        // the error's own key, and the message can live under it.
        const fieldNames = apiErrorFieldNames(err);
        const message = describeApiError(err) ?? `Failed to create ${context}`;

        if (fieldNames.includes("external_id") && context === "Organization") {
          setFieldError(strategy.externalIdField, message);
          setApiError(message);
        } else if (fieldNames.includes("name")) {
          if (!setFieldError("organizationName", message)) {
            setApiError(message);
          }
        } else {
          const secretField =
            context === "Secret"
              ? strategy.mapSecretErrorField(fieldNames)
              : null;
          if (!secretField || !setFieldError(secretField, message)) {
            setApiError(message);
          }
        }
      }
    } else {
      setApiError(extractErrorMessage(result, `Failed to create ${context}`));
    }
  };

  // Timeout no longer sets apiError itself — the caller surfaces the two-action
  // timeout state (keep waiting / retry). Failure/cancellation are terminal.
  const pollDiscoveryResult = async (
    organizationId: string,
    discoveryId: string,
    signal: AbortSignal,
    strategy: BoundOrgSetupStrategy,
  ): Promise<PollOutcome> => {
    for (let attempt = 0; attempt < DISCOVERY_MAX_RETRIES; attempt += 1) {
      if (signal.aborted || !isMountedRef.current) {
        return { kind: "cancelled" };
      }

      const result = await getDiscovery(organizationId, discoveryId);
      if (signal.aborted || !isMountedRef.current) {
        return { kind: "cancelled" };
      }

      if (result?.error) {
        setApiError(strategy.authFailureMessage(result.error));
        return { kind: "failed" };
      }

      const status = result?.data?.attributes?.status;

      if (!status) {
        setApiError(UNEXPECTED_DISCOVERY_RESULT);
        return { kind: "failed" };
      }

      if (status === DISCOVERY_STATUS.SUCCEEDED) {
        return { kind: "resolved", result: result.data.attributes.result };
      }

      if (status === DISCOVERY_STATUS.FAILED) {
        // `attributes.error` is a machine code (`gcp_invalid_organization_id`,
        // `gcp_service_unavailable`, …), not user copy, and only some of them
        // are credential problems.
        setApiError(
          strategy.discoveryFailureMessage(result.data.attributes.error),
        );
        return { kind: "failed" };
      }

      await sleepWithAbort(DISCOVERY_POLL_INTERVAL_MS, signal);
    }

    if (signal.aborted || !isMountedRef.current) {
      return { kind: "cancelled" };
    }

    return { kind: "timeout" };
  };

  // Maps a resolved discovery into the store, seeds the default selection, and
  // advances to the selection step. Shared by initial submit, resume, and retry.
  const applyResolvedDiscovery = (
    discoveryId: string,
    result: unknown,
    strategy: BoundOrgSetupStrategy,
  ) => {
    const { hierarchy, defaultSelection } = strategy.ingestDiscovery(result);
    setDiscovery(discoveryId, hierarchy);
    setSelectedCandidateIds(defaultSelection);
    onNext();
  };

  // Handles a poll outcome uniformly: resolved → advance; timeout → offer
  // keep-waiting/retry; failed/cancelled → nothing more (apiError already set).
  const handlePollOutcome = (
    outcome: PollOutcome,
    discoveryId: string,
    strategy: BoundOrgSetupStrategy,
    signal: AbortSignal,
  ) => {
    if (signal.aborted || !isMountedRef.current) {
      return;
    }
    if (outcome.kind === "resolved") {
      // Ingesting the result is all that is left once discovery succeeded, and a
      // result we cannot map is not a credentials problem
      try {
        applyResolvedDiscovery(discoveryId, outcome.result, strategy);
      } catch {
        setApiError(UNEXPECTED_DISCOVERY_RESULT);
        setDiscoveryFailed(true);
      }
      return;
    }
    if (outcome.kind === "timeout") {
      setDiscoveryTimedOut(true);
      return;
    }
    if (outcome.kind === "failed") {
      setDiscoveryFailed(true);
    }
  };

  const submitOrganizationSetup = async (
    data: OrgSetupSubmissionData,
    options?: SubmitOptions,
  ) => {
    // The form's own tag picks the strategy, so the collected fields and the
    // credentials/discovery built from them always belong to the same type.
    const strategy = bindOrgSetupStrategy(data);
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
        setDiscoveryTimedOut(false);
        setDiscoveryFailed(false);
        setIsSubmissionPending(true);
      }
      clearValidationState();

      const { externalId, resolvedName } = strategy;

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
        orgFormData.set("name", resolvedName);
        orgFormData.set("externalId", externalId);
        orgFormData.set("orgType", strategy.orgType);

        const orgResult = await createOrganization(orgFormData);
        if (isCancelled()) {
          return;
        }

        if (orgResult?.error || orgResult?.errors?.length) {
          handleServerError(orgResult, "Organization", strategy);
          return;
        }

        orgId = orgResult?.data?.id;
      }

      if (!orgId) {
        setApiErrorIfActive(
          "Unable to resolve organization ID for authentication.",
        );
        return;
      }

      const organizationNameForStore =
        existingOrganization?.attributes?.name ?? resolvedName;
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

      // Warn before overwriting an existing credential: replacing it
      // re-authenticates every provider already onboarded under the org.
      if (existingSecretId && !options?.confirmReplace) {
        pendingSubmitDataRef.current = data;
        if (!isCancelled()) {
          setReplaceSecretWarning({
            providerCount: getOrganizationProviderCount(existingOrganization),
          });
        }
        return;
      }

      const secretPayload = strategy.buildSecretPayload(stackSetExternalId);

      const secretResult = existingSecretId
        ? await updateOrganizationSecret(existingSecretId, secretPayload)
        : await createOrganizationSecret(orgId, secretPayload);
      if (isCancelled()) {
        return;
      }

      if (secretResult?.error) {
        handleServerError(secretResult, "Secret", strategy);
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

      const discoveryId = discoveryResult?.data?.id;
      if (!discoveryId) {
        setApiErrorIfActive(UNEXPECTED_DISCOVERY_RESULT);
        return;
      }
      // Persist the discovery id at trigger time so an interrupted discovery
      // can be resumed on wizard re-entry.
      setDiscoveryTriggered(discoveryId);
      resumeContextRef.current = { orgId, discoveryId, strategy };

      const outcome = await pollDiscoveryResult(
        orgId,
        discoveryId,
        abortController.signal,
        strategy,
      );
      // Discovery came back: from here on, credentials are proven good.
      if (outcome.kind === "resolved") {
        hasDiscovered = true;
      }
      handlePollOutcome(outcome, discoveryId, strategy, abortController.signal);
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
      // Only the newest chain clears the flag: if a later one superseded this
      // controller it owns the pending state and is still running.
      if (discoveryAbortControllerRef.current === abortController) {
        discoveryAbortControllerRef.current = null;
        setIsSubmissionPending(false);
      }
    }
  };

  const confirmSecretReplace = () => {
    const data = pendingSubmitDataRef.current;
    setReplaceSecretWarning(null);
    if (data) {
      void submitOrganizationSetup(data, { confirmReplace: true });
    }
  };

  const cancelSecretReplace = () => {
    setReplaceSecretWarning(null);
  };

  // *Keep waiting*: resume polling the SAME discovery with a fresh attempt
  // budget — free, because the worker kept running past the client timeout.
  const keepWaitingForDiscovery = async () => {
    const ctx = resumeContextRef.current;
    if (!ctx) {
      return;
    }
    discoveryAbortControllerRef.current?.abort();
    const abortController = new AbortController();
    discoveryAbortControllerRef.current = abortController;
    setDiscoveryTimedOut(false);
    setDiscoveryFailed(false);
    setIsSubmissionPending(true);

    try {
      const outcome = await pollDiscoveryResult(
        ctx.orgId,
        ctx.discoveryId,
        abortController.signal,
        ctx.strategy,
      );
      handlePollOutcome(
        outcome,
        ctx.discoveryId,
        ctx.strategy,
        abortController.signal,
      );
    } catch {
      if (isMountedRef.current && !abortController.signal.aborted) {
        setApiError(UNEXPECTED_DISCOVERY_RESULT);
        // The same discovery is still running server-side, so restore the
        // two-action notice rather than forcing a fresh POST /discoveries.
        setDiscoveryTimedOut(true);
      }
    } finally {
      // Only the newest chain clears the flag: if a later one superseded this
      // controller it owns the pending state and is still running.
      if (discoveryAbortControllerRef.current === abortController) {
        discoveryAbortControllerRef.current = null;
        setIsSubmissionPending(false);
      }
    }
  };

  // *Retry*: trigger a NEW discovery on the same organization (a fresh snapshot
  // that re-hits Cloud Resource Manager), then poll it.
  const retryDiscovery = async () => {
    const ctx = resumeContextRef.current;
    if (!ctx) {
      return;
    }
    discoveryAbortControllerRef.current?.abort();
    const abortController = new AbortController();
    discoveryAbortControllerRef.current = abortController;
    setDiscoveryTimedOut(false);
    setDiscoveryFailed(false);
    setIsSubmissionPending(true);
    setApiError(null);

    try {
      const discoveryResult = await triggerDiscovery(ctx.orgId);
      if (abortController.signal.aborted || !isMountedRef.current) {
        return;
      }
      if (discoveryResult?.error) {
        setApiError(discoveryResult.error);
        // A retry that could not even be triggered is itself a discovery
        // failure: without this the retry button we were clicked from vanishes.
        setDiscoveryFailed(true);
        return;
      }

      const discoveryId = discoveryResult?.data?.id;
      if (!discoveryId) {
        setApiError(UNEXPECTED_DISCOVERY_RESULT);
        setDiscoveryFailed(true);
        return;
      }
      setDiscoveryTriggered(discoveryId);
      resumeContextRef.current = { ...ctx, discoveryId };

      const outcome = await pollDiscoveryResult(
        ctx.orgId,
        discoveryId,
        abortController.signal,
        ctx.strategy,
      );
      handlePollOutcome(
        outcome,
        discoveryId,
        ctx.strategy,
        abortController.signal,
      );
    } catch {
      if (isMountedRef.current && !abortController.signal.aborted) {
        // Reaching a retry means the credentials were already accepted once, so
        // this cannot be an authentication problem.
        setApiError(UNEXPECTED_DISCOVERY_RESULT);
        setDiscoveryFailed(true);
      }
    } finally {
      // Only the newest chain clears the flag: if a later one superseded this
      // controller it owns the pending state and is still running.
      if (discoveryAbortControllerRef.current === abortController) {
        discoveryAbortControllerRef.current = null;
        setIsSubmissionPending(false);
      }
    }
  };

  return {
    apiError,
    setApiError,
    submitOrganizationSetup,
    replaceSecretWarning,
    confirmSecretReplace,
    cancelSecretReplace,
    discoveryTimedOut,
    discoveryFailed,
    isSubmissionPending,
    keepWaitingForDiscovery,
    retryDiscovery,
  };
}
