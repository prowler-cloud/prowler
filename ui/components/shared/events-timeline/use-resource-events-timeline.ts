"use client";

import { useEffect, useState, useTransition } from "react";

import { getResourceEvents } from "@/actions/resources";
import { ResourceEventProps } from "@/types";

interface UseResourceEventsTimelineOptions {
  resourceId?: string;
  isAwsProvider: boolean;
  includeReadEvents: boolean;
  retryCount: number;
}

interface UseResourceEventsTimelineReturn {
  events: ResourceEventProps[];
  error: string | null;
  errorStatus: number | null;
  hasFetched: boolean;
  isPending: boolean;
}

export function useResourceEventsTimeline({
  resourceId,
  isAwsProvider,
  includeReadEvents,
  retryCount,
}: UseResourceEventsTimelineOptions): UseResourceEventsTimelineReturn {
  const [events, setEvents] = useState<ResourceEventProps[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [errorStatus, setErrorStatus] = useState<number | null>(null);
  const [hasFetched, setHasFetched] = useState(false);
  const [isPending, startTransition] = useTransition();

  useEffect(() => {
    if (!isAwsProvider || !resourceId) return;

    let cancelled = false;

    setError(null);
    setErrorStatus(null);
    setHasFetched(false);

    startTransition(async () => {
      try {
        const response = await getResourceEvents(resourceId, {
          includeReadEvents,
        });

        if (cancelled) return;

        if (!response) {
          setError("Failed to fetch events. Please try again.");
          return;
        }

        if (response.error) {
          setError(response.error);
          setErrorStatus(response.status || null);
          return;
        }

        setEvents(response.data || []);
      } catch (err) {
        if (cancelled) return;
        console.error("Error fetching events:", err);
        setError("An unexpected error occurred.");
      } finally {
        if (!cancelled) setHasFetched(true);
      }
    });

    return () => {
      cancelled = true;
    };
  }, [resourceId, includeReadEvents, isAwsProvider, retryCount]);

  return {
    events,
    error,
    errorStatus,
    hasFetched,
    isPending,
  };
}
