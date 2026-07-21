import { createStore, type StoreApi } from "zustand/vanilla";

import {
  createLighthouseV2Session,
  getLighthouseV2Messages,
  sendLighthouseV2Message,
  updateLighthouseV2Configuration,
} from "@/app/(prowler)/lighthouse/_actions";
import {
  createInitialLighthouseV2StreamState,
  type LighthouseV2StreamState,
  reduceLighthouseV2Event,
} from "@/app/(prowler)/lighthouse/_lib/event-reducer";
import {
  buildOptimisticMessage,
  buildSessionTitle,
} from "@/app/(prowler)/lighthouse/_lib/messages";
import type { LighthouseV2ModelSelection } from "@/app/(prowler)/lighthouse/_lib/model-selection";
import { notifyLighthouseV2SessionsChanged } from "@/app/(prowler)/lighthouse/_lib/session-events";
import { parseStreamEvent } from "@/app/(prowler)/lighthouse/_lib/stream-event-parser";
import { buildLighthouseV2StreamUrl } from "@/app/(prowler)/lighthouse/_lib/stream-url";
import {
  LIGHTHOUSE_V2_PROVIDER_TYPE,
  LIGHTHOUSE_V2_SSE_EVENT,
  type LighthouseV2Configuration,
  type LighthouseV2Message,
  type LighthouseV2ProviderType,
  type LighthouseV2SSEEvent,
  type LighthouseV2SupportedModel,
  type LighthouseV2SupportedProvider,
} from "@/app/(prowler)/lighthouse/_types";
import { prepareLighthouseContext } from "@/lib/lighthouse/context/compiler";
import type { LighthouseContextEnvelope } from "@/types/lighthouse-context";

export interface LighthouseChatConfig {
  configurations: LighthouseV2Configuration[];
  modelsByProvider: Record<
    LighthouseV2ProviderType,
    LighthouseV2SupportedModel[]
  >;
  supportedProviders: LighthouseV2SupportedProvider[];
}

export interface CreateLighthouseChatStoreOptions {
  config: LighthouseChatConfig;
  // The /lighthouse page mirrors the active session into the URL via
  // replaceState; other surfaces (side panel, drawers) must never touch it.
  syncUrlToSession: boolean;
  initialSessionId?: string;
  initialMessages?: LighthouseV2Message[];
  initialInput?: string;
  initialError?: string;
}

export interface LighthouseChatState {
  config: LighthouseChatConfig;
  activeSessionId: string | null;
  messages: LighthouseV2Message[];
  streamState: LighthouseV2StreamState;
  input: string;
  feedback: string | null;
  blockedByConflict: boolean;
  isSubmitting: boolean;
  isLoadingSession: boolean;
  /** @deprecated Use lastSubmission so retries can preserve their context snapshot. */
  lastSubmittedText: string | null;
  lastSubmission: LighthouseChatSubmission | null;
  isContextEnabled: boolean;
  selectedModelSelection: LighthouseV2ModelSelection | null;
  modelPreferenceSaving: boolean;
  setSessionUrlSyncEnabled: (enabled: boolean) => void;
  setInput: (value: string) => void;
  dismissFeedback: () => void;
  selectModel: (selection: LighthouseV2ModelSelection) => Promise<void>;
  submitMessage: (
    displayText: string,
    context?: LighthouseContextEnvelope,
  ) => Promise<void>;
  retryLastMessage: () => Promise<void>;
  disableContext: () => void;
  enableContext: () => void;
  openSession: (sessionId: string) => Promise<void>;
  resetToNewChat: () => void;
  handleSessionArchived: (sessionId: string) => void;
  destroy: () => void;
}

export interface LighthouseChatSubmission {
  displayText: string;
  context?: LighthouseContextEnvelope;
}

export type LighthouseChatStore = StoreApi<LighthouseChatState>;

export function selectLighthouseChatCanSend(
  state: LighthouseChatState,
): boolean {
  const selectedConfiguration = state.config.configurations.find(
    (configuration) =>
      configuration.connected === true &&
      configuration.providerType === state.selectedModelSelection?.providerType,
  );
  return (
    selectedConfiguration?.connected === true &&
    Boolean(state.selectedModelSelection?.modelId) &&
    !state.streamState.activeTaskId &&
    !state.blockedByConflict &&
    !state.isSubmitting
  );
}

export function createLighthouseChatStore(
  options: CreateLighthouseChatStoreOptions,
): LighthouseChatStore {
  const { config } = options;
  const connectedConfigurations = config.configurations.filter(
    (configuration) => configuration.connected === true,
  );
  // The EventSource lives in this closure (never in state): it isn't
  // serializable, no render depends on it, and here it survives the consuming
  // component unmounting — the reason this factory exists.
  let eventSource: EventSource | null = null;
  // Set by destroy(): async flows check it after each await so a torn-down
  // store never rewrites the URL of another page or opens an orphan stream.
  let destroyed = false;
  // User-driven session changes invalidate async session creation. Comparing
  // only activeSessionId is insufficient because both the initial chat and a
  // later reset intentionally use null.
  let sessionIntentVersion = 0;
  let syncUrlToSession = options.syncUrlToSession;
  // Retry must reuse the original validated snapshot even if the user has
  // since disabled context for future messages. Kept in the store closure so
  // the UI-facing enabled flag never flickers during the async retry.
  let retryContextOverride: LighthouseContextEnvelope | undefined;

  const syncSessionUrl = (sessionId: string | null) => {
    if (!syncUrlToSession) return;
    const url = sessionId
      ? `/lighthouse?session=${encodeURIComponent(sessionId)}`
      : "/lighthouse";
    window.history.replaceState(window.history.state, "", url);
  };

  return createStore<LighthouseChatState>()((set, get) => {
    const closeStream = () => {
      eventSource?.close();
      eventSource = null;
    };

    const refreshMessages = async (
      sessionId: string,
      shouldApply: () => boolean = () => true,
    ): Promise<boolean> => {
      const result = await getLighthouseV2Messages(sessionId);
      // The fetch is async, so a reset (new chat, or archiving this session)
      // can land while it is in flight. Drop the stale result instead of
      // repopulating a chat that no longer points at this session.
      if (sessionId !== get().activeSessionId || !shouldApply()) return false;
      if ("data" in result) {
        set({ messages: result.data });
        return true;
      }
      return false;
    };

    const handleTerminalEvent = async (
      sessionId: string,
      event: LighthouseV2SSEEvent,
    ) => {
      if (
        event.type === LIGHTHOUSE_V2_SSE_EVENT.MESSAGE_END ||
        event.type === LIGHTHOUSE_V2_SSE_EVENT.ERROR
      ) {
        closeStream();
        set({ blockedByConflict: false });
        if (event.type === LIGHTHOUSE_V2_SSE_EVENT.ERROR) {
          set({ feedback: event.detail || "Agent run failed." });
        }
        // A fast follow-up can start while this refresh is in flight; applying
        // it would erase the new optimistic message and provisional task id.
        const noNewerSubmission = () =>
          !get().isSubmitting && !get().streamState.activeTaskId;
        const refreshed = await refreshMessages(sessionId, noNewerSubmission);
        if (refreshed) {
          set({ streamState: createInitialLighthouseV2StreamState() });
        }
        notifyLighthouseV2SessionsChanged();
      }
    };

    const startStream = (streamUrl: string, sessionId: string) => {
      closeStream();
      const source = new EventSource(streamUrl);
      eventSource = source;

      const applyEvent = (event: LighthouseV2SSEEvent) => {
        set((current) => ({
          streamState: reduceLighthouseV2Event(current.streamState, event),
        }));
        void handleTerminalEvent(sessionId, event);
      };

      source.addEventListener("message.delta", (event) =>
        applyEvent(
          parseStreamEvent(event, LIGHTHOUSE_V2_SSE_EVENT.MESSAGE_DELTA),
        ),
      );
      source.addEventListener("tool_call.start", (event) =>
        applyEvent(
          parseStreamEvent(event, LIGHTHOUSE_V2_SSE_EVENT.TOOL_CALL_START),
        ),
      );
      source.addEventListener("tool_call.end", (event) =>
        applyEvent(
          parseStreamEvent(event, LIGHTHOUSE_V2_SSE_EVENT.TOOL_CALL_END),
        ),
      );
      source.addEventListener("message.end", (event) =>
        applyEvent(
          parseStreamEvent(event, LIGHTHOUSE_V2_SSE_EVENT.MESSAGE_END),
        ),
      );
      source.addEventListener("error", (event) => {
        if (event instanceof MessageEvent) {
          applyEvent(parseStreamEvent(event, LIGHTHOUSE_V2_SSE_EVENT.ERROR));
        }
      });
      // The browser fires `onerror` both on a transient drop (it auto-reconnects)
      // and on a non-retryable failure such as a 401/404 on the SSE GET. Only the
      // latter leaves the source CLOSED, so surface a connection error there and
      // treat everything else as a reconnect.
      source.onerror = () => {
        if (eventSource !== source) return;
        if (source.readyState === EventSource.CLOSED) {
          closeStream();
          set({ feedback: "Unable to connect to the response stream." });
        }
        set((current) => ({
          streamState: reduceLighthouseV2Event(current.streamState, {
            type: "disconnect",
          }),
        }));
      };
    };

    const ensureSession = async (text: string) => {
      const existingSessionId = get().activeSessionId;
      if (existingSessionId) {
        return existingSessionId;
      }

      const intentVersion = sessionIntentVersion;
      const title = buildSessionTitle(text);
      const result = await createLighthouseV2Session(title);
      if (destroyed || intentVersion !== sessionIntentVersion) return null;
      if ("error" in result) {
        set({ feedback: result.error });
        return null;
      }

      // Update the URL in place (not router.push) so the force-dynamic server
      // component is NOT re-run mid-submit. A re-run would change `key` in
      // page.tsx and remount the chat, tearing down the open EventSource.
      syncSessionUrl(result.data.id);
      set({ activeSessionId: result.data.id });
      notifyLighthouseV2SessionsChanged();
      return result.data.id;
    };

    return {
      config,
      activeSessionId: options.initialSessionId ?? null,
      messages: options.initialMessages ?? [],
      streamState: createInitialLighthouseV2StreamState(),
      input: options.initialInput ?? "",
      feedback: options.initialError ?? null,
      blockedByConflict: false,
      isSubmitting: false,
      isLoadingSession: false,
      lastSubmittedText: null,
      lastSubmission: null,
      isContextEnabled: true,
      selectedModelSelection: resolveInitialModelSelection(
        connectedConfigurations,
        config.modelsByProvider,
      ),
      modelPreferenceSaving: false,

      setSessionUrlSyncEnabled: (enabled) => {
        syncUrlToSession = enabled;
      },

      setInput: (value) => set({ input: value }),

      dismissFeedback: () => set({ feedback: null }),

      disableContext: () => set({ isContextEnabled: false }),

      enableContext: () => set({ isContextEnabled: true }),

      selectModel: async (selection) => {
        // The selection drives the model used for the next message, so it stays
        // applied even if persisting it as the provider's default model fails —
        // reverting it would make a connected provider unusable when the save 4xxs.
        set({ selectedModelSelection: selection, feedback: null });

        const configId = connectedConfigurations.find(
          (configuration) =>
            configuration.providerType === selection.providerType,
        )?.id;
        if (!configId) return;

        set({ modelPreferenceSaving: true });

        const result = await updateLighthouseV2Configuration(configId, {
          defaultModel: selection.modelId,
        });

        set({ modelPreferenceSaving: false });

        if ("error" in result) {
          set({ feedback: result.error });
        }
      },

      submitMessage: async (displayText, context) => {
        if (!displayText.trim()) return;
        if (!get().selectedModelSelection) {
          set({ feedback: "Select a model before sending a message." });
          return;
        }
        if (!selectLighthouseChatCanSend(get())) return;

        const contextCandidate =
          retryContextOverride ??
          (get().isContextEnabled && context ? context : undefined);
        const contextSnapshot = contextCandidate
          ? prepareLighthouseContext(contextCandidate)
          : undefined;

        set({ isSubmitting: true });
        try {
          const sessionId = await ensureSession(displayText);
          if (!sessionId || destroyed) return;

          const selection = get().selectedModelSelection;
          if (!selection) return;

          const provisionalTaskId = `pending-${Date.now()}`;
          const lastSubmission = contextSnapshot
            ? { displayText, context: contextSnapshot }
            : { displayText };
          set((current) => ({
            feedback: null,
            blockedByConflict: false,
            lastSubmittedText: displayText,
            lastSubmission,
            input: "",
            messages: [
              ...current.messages,
              buildOptimisticMessage("user", displayText, contextSnapshot),
            ],
            streamState:
              createInitialLighthouseV2StreamState(provisionalTaskId),
          }));

          // Subscribe to the same-origin SSE proxy BEFORE sending the message:
          // the backend has no replay buffer, so the listener must be attached
          // before the worker starts emitting.
          startStream(buildLighthouseV2StreamUrl(sessionId), sessionId);

          const result = await sendLighthouseV2Message({
            sessionId,
            displayText,
            ...(contextSnapshot ? { context: contextSnapshot } : {}),
            provider: selection.providerType,
            model: selection.modelId,
          });
          if (destroyed) return;

          if ("error" in result) {
            // Stale guard: the chat may point at another session by now, so
            // this failure must not clobber its stream state or feedback.
            if (get().activeSessionId !== sessionId) return;
            closeStream();
            set({
              streamState: createInitialLighthouseV2StreamState(),
              feedback: result.error,
            });
            if (result.status === 409) {
              set({ blockedByConflict: true });
            }
            // Reconcile the optimistic user message against the server on any
            // failure — it may or may not have been persisted.
            await refreshMessages(sessionId);
            return;
          }

          set((current) => ({
            streamState:
              current.streamState.activeTaskId === provisionalTaskId
                ? { ...current.streamState, activeTaskId: result.data.task.id }
                : current.streamState,
          }));
          notifyLighthouseV2SessionsChanged();
        } finally {
          set({ isSubmitting: false });
        }
      },

      retryLastMessage: async () => {
        const submission = get().lastSubmission;
        if (!submission) return;
        retryContextOverride = submission.context;
        try {
          await get().submitMessage(submission.displayText, submission.context);
        } finally {
          retryContextOverride = undefined;
        }
      },

      openSession: async (sessionId) => {
        if (get().activeSessionId === sessionId) return;
        sessionIntentVersion += 1;
        closeStream();
        set({
          activeSessionId: sessionId,
          messages: [],
          input: "",
          feedback: null,
          blockedByConflict: false,
          isSubmitting: false,
          isLoadingSession: true,
          lastSubmittedText: null,
          lastSubmission: null,
          isContextEnabled: true,
          streamState: createInitialLighthouseV2StreamState(),
        });
        syncSessionUrl(sessionId);

        const result = await getLighthouseV2Messages(sessionId);
        // Stale guard: a reset or another openSession can land mid-fetch.
        if (get().activeSessionId !== sessionId) return;
        if ("data" in result) {
          set({ messages: result.data, isLoadingSession: false });
        } else {
          set({ feedback: result.error, isLoadingSession: false });
        }
      },

      resetToNewChat: () => {
        sessionIntentVersion += 1;
        closeStream();
        set({
          activeSessionId: null,
          messages: [],
          input: "",
          feedback: null,
          blockedByConflict: false,
          isSubmitting: false,
          isLoadingSession: false,
          lastSubmittedText: null,
          lastSubmission: null,
          isContextEnabled: true,
          streamState: createInitialLighthouseV2StreamState(),
        });
        syncSessionUrl(null);
      },

      handleSessionArchived: (sessionId) => {
        // Archiving deletes the session; when it's the open one, fall back to a
        // new chat instead of leaving a dead conversation on screen.
        if (sessionId === get().activeSessionId) {
          get().resetToNewChat();
        }
      },

      destroy: () => {
        destroyed = true;
        closeStream();
      },
    };
  });
}

// Fixed precedence used to pick which connected provider opens the chat. Any
// provider outside this list keeps its relative order behind these.
const LIGHTHOUSE_V2_PROVIDER_PRIORITY = [
  LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI,
  LIGHTHOUSE_V2_PROVIDER_TYPE.BEDROCK,
  LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI_COMPATIBLE,
] as const;

// Fallback model per provider when the configuration has no remembered model.
const LIGHTHOUSE_V2_PREFERRED_DEFAULT_MODEL: Partial<
  Record<LighthouseV2ProviderType, string>
> = {
  [LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI]: "gpt-5.6-terra",
};

function resolveInitialModelSelection(
  connectedConfigurations: LighthouseV2Configuration[],
  modelsByProvider: Record<
    LighthouseV2ProviderType,
    LighthouseV2SupportedModel[]
  >,
): LighthouseV2ModelSelection | null {
  const priorityIndex = (providerType: LighthouseV2ProviderType) => {
    const index = LIGHTHOUSE_V2_PROVIDER_PRIORITY.indexOf(providerType);
    return index === -1 ? LIGHTHOUSE_V2_PROVIDER_PRIORITY.length : index;
  };
  // Stable sort keeps providers outside the priority list in their original order.
  const orderedConfigurations = [...connectedConfigurations].sort(
    (a, b) => priorityIndex(a.providerType) - priorityIndex(b.providerType),
  );

  for (const configuration of orderedConfigurations) {
    const providerModels = modelsByProvider[configuration.providerType] ?? [];
    if (providerModels.length === 0) continue;
    // Prefer the provider's remembered model when it is still supported, then
    // the provider's preferred default, then the first supported model.
    const rememberedModel = providerModels.find(
      (model) => model.id === configuration.defaultModel,
    );
    const preferredModel = providerModels.find(
      (model) =>
        model.id ===
        LIGHTHOUSE_V2_PREFERRED_DEFAULT_MODEL[configuration.providerType],
    );
    return {
      providerType: configuration.providerType,
      modelId: (rememberedModel ?? preferredModel ?? providerModels[0]).id,
    };
  }

  return null;
}
