"use client";

import { useRef, useState } from "react";

import { useMountEffect } from "@/hooks/use-mount-effect";
import { testProviderConnection } from "@/lib/provider-helpers";
import { CONNECTION_CHECK_STATUS } from "@/types/providers";

const CONNECTION_FAILED_MESSAGE =
  "Prowler could not connect with these credentials. Review them and try again.";

const CONNECTION_UNREACHABLE_MESSAGE =
  "The connection test could not be completed. The account is saved, so you can try again.";

// Fallback only: `testProviderConnection` already carries this same message on
// `error` for a pending result (see `resolveProviderConnectionState`).
const CONNECTION_PENDING_MESSAGE =
  "The connection test is still running. Refresh in a moment to see the result.";

/** Footer label for the one-step form: the test and the retry share the submit. */
export const resolveConnectActionLabel = ({
  submitLabel,
  isTesting,
  isSubmitting,
  hasFailed,
  hasPending,
}: {
  submitLabel: string;
  isTesting: boolean;
  isSubmitting: boolean;
  hasFailed: boolean;
  hasPending: boolean;
}) => {
  if (isTesting) return "Testing connection...";
  if (isSubmitting) return "Connecting...";
  if (hasFailed) return "Retry connection";
  return hasPending ? "Check again" : submitLabel;
};

/** Tests a saved account and keeps the verdict for the step to show. */
export function useConnectionCheck(onConnected: () => void) {
  // Local state needed: the test outcome belongs to the step, not to any field.
  const [isTesting, setIsTesting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Still running past the wait: neither a pass nor a fail, so it never takes
  // the destructive styling a confirmed failure gets.
  const [pending, setPending] = useState<string | null>(null);
  // Closing the wizard (or switching to organizations) unmounts the step while a
  // test may still be running; its result must not advance a wizard already reset.
  const isActiveRef = useRef(true);
  useMountEffect(() => {
    isActiveRef.current = true;
    return () => {
      isActiveRef.current = false;
    };
  });

  const clear = () => {
    setError(null);
    setPending(null);
  };

  // Task polling rejects on a 5xx, so the flag is cleared in a finally or the
  // step would stay stuck on "Testing connection...".
  const check = async (providerId: string) => {
    let connected = false;
    setIsTesting(true);
    try {
      const connection = await testProviderConnection(providerId);
      connected = connection.status === CONNECTION_CHECK_STATUS.SUCCESS;
      if (connection.status === CONNECTION_CHECK_STATUS.FAILED) {
        setError(connection.error || CONNECTION_FAILED_MESSAGE);
      } else if (connection.status === CONNECTION_CHECK_STATUS.PENDING) {
        setPending(connection.error || CONNECTION_PENDING_MESSAGE);
      }
    } catch {
      setError(CONNECTION_UNREACHABLE_MESSAGE);
    } finally {
      setIsTesting(false);
    }

    if (connected && isActiveRef.current) onConnected();
  };

  return { check, clear, isTesting, error, pending };
}
