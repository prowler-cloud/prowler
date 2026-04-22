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
import { getSelectableAccountIds } from "@/actions/organizations/organizations.adapter";
import { useOrgSetupStore } from "@/store/organizations/store";
import { DISCOVERY_STATUS, DiscoveryResult } from "@/types/organizations";

import { extractErrorMessage } from "./error-utils";

const DISCOVERY_POLL_INTERVAL_MS = 3000;
const DISCOVERY_MAX_RETRIES = 60;

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

interface OrgSetupSubmissionData {
  organizationName?: string;
  awsOrgId: string;
  roleArn: string;
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
    setDiscovery,
    setSelectedAccountIds,
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
  ): Promise<DiscoveryResult | null> => {
    for (let attempt = 0; attempt < DISCOVERY_MAX_RETRIES; attempt += 1) {
      if (signal.aborted || !isMountedRef.current) {
        return null;
      }

      const result = await getDiscovery(organizationId, discoveryId);
      if (signal.aborted || !isMountedRef.current) {
        return null;
      }

      if (result?.error) {
        setApiError(
          `Authentication failed. Please verify the StackSet deployment and Role ARN, then try again. ${result.error}`,
        );
        return null;
      }

      const status = result.data.attributes.status;

      if (status === DISCOVERY_STATUS.SUCCEEDED) {
        return result.data.attributes.result as DiscoveryResult;
      }

      if (status === DISCOVERY_STATUS.FAILED) {
        const backendError = result.data.attributes.error;
        setApiError(
          backendError
            ? `Authentication failed. Please verify the StackSet deployment and Role ARN, then try again. ${backendError}`
            : "Authentication failed. Please verify the StackSet deployment and Role ARN, then try again.",
        );
        return null;
      }

      await sleepWithAbort(DISCOVERY_POLL_INTERVAL_MS, signal);
    }

    if (signal.aborted || !isMountedRef.current) {
      return null;
    }

    setApiError(
      "Authentication timed out. Please verify the credentials and try again.",
    );
    return null;
  };

  const submitOrganizationSetup = async (data: OrgSetupSubmissionData) => {
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

    try {
      if (!isCancelled()) {
        setApiError(null);
      }
      clearValidationState();

      const resolvedOrganizationName =
        data.organizationName?.trim() || data.awsOrgId;

      const existingOrganizationsResult = await listOrganizationsByExternalId(
        data.awsOrgId,
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
              organization?.attributes?.external_id === data.awsOrgId &&
              organization?.attributes?.org_type === "aws",
          )
        : null;

      let orgId = existingOrganization?.id as string | undefined;

      if (!orgId) {
        const orgFormData = new FormData();
        orgFormData.set("name", resolvedOrganizationName);
        orgFormData.set("externalId", data.awsOrgId);

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
      setOrganization(orgId, organizationNameForStore, data.awsOrgId);

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

      let secretResult;
      if (existingSecretId) {
        const patchSecretFormData = new FormData();
        patchSecretFormData.set("organizationSecretId", existingSecretId);
        patchSecretFormData.set("roleArn", data.roleArn);
        patchSecretFormData.set("externalId", stackSetExternalId);
        secretResult = await updateOrganizationSecret(patchSecretFormData);
      } else {
        const createSecretFormData = new FormData();
        createSecretFormData.set("organizationId", orgId);
        createSecretFormData.set("roleArn", data.roleArn);
        createSecretFormData.set("externalId", stackSetExternalId);
        secretResult = await createOrganizationSecret(createSecretFormData);
      }
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
      const resolvedDiscoveryResult = await pollDiscoveryResult(
        orgId,
        discoveryId,
        abortController.signal,
      );

      if (!resolvedDiscoveryResult || isCancelled()) {
        return;
      }

      const selectableAccountIds = getSelectableAccountIds(
        resolvedDiscoveryResult,
      );
      setDiscovery(discoveryId, resolvedDiscoveryResult);
      setSelectedAccountIds(selectableAccountIds);
      onNext();
    } catch {
      if (!isCancelled()) {
        setApiError(
          "Authentication failed. Please verify the StackSet deployment and Role ARN, then try again.",
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
