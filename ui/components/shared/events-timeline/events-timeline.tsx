"use client";

import {
  AlertTriangle,
  ChevronRight,
  Clock,
  Download,
  Loader2,
  Server,
  Shield,
} from "lucide-react";
import { useEffect, useState, useTransition } from "react";

import { getResourceEvents } from "@/actions/resources";
import {
  Alert,
  AlertDescription,
  Badge,
  Button,
  Card,
  Checkbox,
  InfoField,
} from "@/components/shadcn";
import { CodeSnippet } from "@/components/ui/code-snippet/code-snippet";
import { cn } from "@/lib/utils";
import { ResourceEventProps } from "@/types";

interface EventsTimelineProps {
  resourceId?: string;
  isAwsProvider: boolean;
}

export const EventsTimeline = ({
  resourceId,
  isAwsProvider,
}: EventsTimelineProps) => {
  const [events, setEvents] = useState<ResourceEventProps[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [errorStatus, setErrorStatus] = useState<number | null>(null);
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());
  const [includeReadEvents, setIncludeReadEvents] = useState(false);
  const [hasFetched, setHasFetched] = useState(false);
  const [retryCount, setRetryCount] = useState(0);
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
        setExpandedRows(new Set());
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

  const toggleRow = (eventId: string) => {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      if (next.has(eventId)) {
        next.delete(eventId);
      } else {
        next.add(eventId);
      }
      return next;
    });
  };

  const downloadEventJson = (event: ResourceEventProps) => {
    const json = JSON.stringify(event.attributes, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `event-${event.attributes.event_name}-${event.attributes.event_time}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 100);
  };

  if (!isAwsProvider) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 py-12">
        <div className="bg-bg-neutral-tertiary/50 rounded-full p-3">
          <Shield className="text-text-neutral-tertiary h-6 w-6" />
        </div>
        <p className="text-text-neutral-secondary text-sm">
          Events timeline is only available for AWS resources.
        </p>
      </div>
    );
  }

  if (isPending && !hasFetched) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 py-12">
        <Loader2 className="size-6 animate-spin" />
        <p className="text-text-neutral-secondary text-sm">
          Fetching CloudTrail events...
        </p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 py-12">
        <Alert variant="error" className="max-w-sm">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            <p>
              {errorStatus === 502
                ? "Provider credentials are invalid or expired. Please reconnect your AWS provider."
                : errorStatus === 503
                  ? "AWS CloudTrail is temporarily unavailable. Please try again later."
                  : error}
            </p>
            <Button
              variant="link"
              size="link-sm"
              onClick={() => setRetryCount((c) => c + 1)}
              aria-label="Retry fetching CloudTrail events"
              className="mt-1"
            >
              Try again
            </Button>
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      {/* Controls bar */}
      <div className="flex items-center justify-between">
        <label className="flex cursor-pointer items-center gap-2">
          <Checkbox
            checked={includeReadEvents}
            onCheckedChange={(checked) =>
              setIncludeReadEvents(checked === true)
            }
            size="sm"
          />
          <span className="text-text-neutral-tertiary text-xs">
            Include read events
          </span>
        </label>
        <div className="flex items-center gap-2">
          {isPending && <Loader2 className="size-4 animate-spin" />}
          <span className="text-text-neutral-tertiary text-xs">
            {events.length} event{events.length !== 1 && "s"}
          </span>
        </div>
      </div>

      {/* Timeline */}
      {events.length === 0 && hasFetched ? (
        <div className="flex flex-col items-center justify-center gap-3 py-12">
          <div className="bg-bg-neutral-tertiary/50 rounded-full p-3">
            <Clock className="text-text-neutral-tertiary h-6 w-6" />
          </div>
          <p className="text-text-neutral-secondary text-sm">
            No events found in the last 90 days.
          </p>
          <p className="text-text-neutral-tertiary max-w-xs text-center text-xs">
            CloudTrail events may take up to 15 minutes to appear after an
            action is performed.
          </p>
        </div>
      ) : (
        <div className="relative ml-3">
          {/* Timeline vertical line */}
          <div className="border-border-neutral-tertiary absolute top-0 bottom-0 left-0 w-px border-l" />

          <div className="flex flex-col">
            {events.map((event, index) => {
              const isExpanded = expandedRows.has(event.id);
              const attrs = event.attributes;
              const hasError = !!attrs.error_code;
              const isLast = index === events.length - 1;

              return (
                <div key={event.id} className={cn(!isLast && "pb-1")}>
                  {/* Timeline node + row */}
                  <button
                    onClick={() => toggleRow(event.id)}
                    aria-expanded={isExpanded}
                    className={cn(
                      "group relative flex w-full items-start gap-4 py-2.5 pr-3 pl-6 text-left transition-colors",
                      "hover:bg-bg-neutral-tertiary/30 rounded-r-lg",
                      "focus-visible:ring-border-neutral-secondary/50 outline-none focus-visible:ring-2 focus-visible:ring-offset-2",
                    )}
                  >
                    {/* Timeline dot */}
                    <div
                      className={cn(
                        "absolute top-[14px] left-0 -translate-x-1/2 rounded-full transition-all",
                        isExpanded
                          ? "bg-button-primary h-3 w-3"
                          : hasError
                            ? "border-border-error-primary bg-bg-fail-secondary h-2.5 w-2.5 border"
                            : "border-border-neutral-tertiary bg-bg-neutral-primary h-2.5 w-2.5 border",
                      )}
                    />

                    {/* Content */}
                    <div className="flex min-w-0 flex-1 items-center gap-3">
                      {/* Time */}
                      <span className="text-text-neutral-tertiary w-[80px] shrink-0 text-xs tabular-nums">
                        {formatShortDate(attrs.event_time)}
                      </span>

                      {/* Event name */}
                      <span
                        className={cn(
                          "text-text-neutral-primary shrink-0 text-sm font-medium",
                          hasError && "text-text-error",
                        )}
                      >
                        {attrs.event_name}
                      </span>

                      {/* Source (dimmed) */}
                      <span className="text-text-neutral-tertiary hidden truncate text-xs lg:inline">
                        {attrs.event_source}
                      </span>

                      <span className="flex-1" />

                      {/* Actor */}
                      <span className="text-text-neutral-tertiary hidden max-w-[200px] truncate text-right font-mono text-xs md:inline">
                        {attrs.actor}
                      </span>

                      <ChevronRight
                        className={cn(
                          "text-text-neutral-tertiary h-4 w-4 shrink-0 transition-transform duration-200",
                          isExpanded && "rotate-90",
                        )}
                      />
                    </div>
                  </button>

                  {/* Expanded detail card */}
                  {isExpanded && (
                    <div className="relative mt-1 mb-2 ml-6">
                      <Card
                        variant="inner"
                        padding="none"
                        className="gap-0 overflow-hidden"
                      >
                        {/* Header bar */}
                        <div className="bg-bg-neutral-tertiary/40 flex items-center justify-between px-5 py-3">
                          <div className="flex items-center gap-2.5">
                            <Server className="text-text-neutral-tertiary h-4 w-4" />
                            <span className="text-text-neutral-primary text-sm font-medium">
                              {attrs.event_name}
                            </span>
                            <span className="text-text-neutral-tertiary text-xs">
                              via {attrs.event_source}
                            </span>
                          </div>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={(e) => {
                              e.stopPropagation();
                              downloadEventJson(event);
                            }}
                            aria-label={`Download ${attrs.event_name} event as JSON`}
                          >
                            <Download className="h-3.5 w-3.5" />
                            JSON
                          </Button>
                        </div>

                        {/* Detail rows */}
                        <div className="divide-border-neutral-tertiary/50 divide-y px-5">
                          <div className="py-2.5">
                            <InfoField label="When" inline>
                              {new Date(attrs.event_time).toLocaleString()}
                            </InfoField>
                          </div>
                          <div className="py-2.5">
                            <InfoField label="Who" inline>
                              <div className="flex items-center gap-2">
                                <span className="text-text-neutral-primary text-xs">
                                  {attrs.actor}
                                </span>
                                <Badge variant="tag">{attrs.actor_type}</Badge>
                              </div>
                            </InfoField>
                          </div>
                          <div className="py-2.5">
                            <InfoField label="From" inline>
                              <span className="font-mono">
                                {attrs.source_ip_address}
                              </span>
                            </InfoField>
                          </div>
                        </div>

                        {/* Error banner */}
                        {hasError && (
                          <Alert
                            variant="error"
                            className="rounded-none border-x-0 border-b-0"
                          >
                            <AlertTriangle className="h-3.5 w-3.5" />
                            <AlertDescription>
                              <span className="text-xs font-medium">
                                {attrs.error_code}
                              </span>
                              {attrs.error_message && (
                                <>
                                  <span className="text-text-error/30">
                                    {" "}
                                    |{" "}
                                  </span>
                                  <span className="text-text-error/70 text-xs">
                                    {attrs.error_message}
                                  </span>
                                </>
                              )}
                            </AlertDescription>
                          </Alert>
                        )}

                        {/* JSON payloads */}
                        {(attrs.request_data || attrs.response_data) && (
                          <div className="border-border-neutral-tertiary/50 flex flex-col gap-4 border-t p-5">
                            {attrs.request_data && (
                              <JsonBlock
                                label="Request"
                                data={attrs.request_data}
                              />
                            )}
                            {attrs.response_data && (
                              <JsonBlock
                                label="Response"
                                data={attrs.response_data}
                              />
                            )}
                          </div>
                        )}
                      </Card>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

// --- Sub-components ---

const JsonBlock = ({
  label,
  data,
}: {
  label: string;
  data: Record<string, unknown>;
}) => {
  const [collapsed, setCollapsed] = useState(true);
  const json = JSON.stringify(data, null, 2);
  const lineCount = json.split("\n").length;
  const isLong = lineCount > 8;

  return (
    <div>
      <div className="mb-1.5 flex items-center justify-between">
        <span className="text-text-neutral-tertiary text-xs font-medium">
          {label}
        </span>
        <CodeSnippet value={json} hideCode />
      </div>
      <div className="bg-bg-neutral-tertiary border-border-neutral-tertiary relative overflow-hidden rounded-md border">
        <pre
          className={cn(
            "minimal-scrollbar overflow-auto p-4 font-mono text-xs leading-relaxed",
            isLong && collapsed && "max-h-[180px]",
          )}
        >
          {json}
        </pre>
        {isLong && collapsed && (
          <div className="from-bg-neutral-tertiary/0 via-bg-neutral-tertiary to-bg-neutral-tertiary absolute inset-x-0 bottom-0 flex items-end justify-center bg-gradient-to-b pt-8 pb-2">
            <Button
              variant="link"
              size="link-sm"
              onClick={(e) => {
                e.stopPropagation();
                setCollapsed(false);
              }}
            >
              Show all ({lineCount} lines)
            </Button>
          </div>
        )}
      </div>
    </div>
  );
};

// --- Helpers ---

const dateFmt = new Intl.DateTimeFormat(undefined, {
  month: "short",
  day: "numeric",
});
const timeFmt = new Intl.DateTimeFormat(undefined, {
  hour: "2-digit",
  minute: "2-digit",
});

const formatShortDate = (iso: string) => {
  const d = new Date(iso);
  return `${dateFmt.format(d)} ${timeFmt.format(d)}`;
};
