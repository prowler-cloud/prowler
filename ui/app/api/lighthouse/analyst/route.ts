import * as Sentry from "@sentry/nextjs";
import { createUIMessageStreamResponse, UIMessage } from "ai";

import { getTenantConfig } from "@/actions/lighthouse/lighthouse";
import { auth } from "@/auth.config";
import { getErrorMessage } from "@/lib/helper";
import {
  CHAIN_OF_THOUGHT_ACTIONS,
  createTextDeltaEvent,
  createTextEndEvent,
  createTextStartEvent,
  ERROR_PREFIX,
  handleChatModelEndEvent,
  handleChatModelStreamEvent,
  handleToolEvent,
  STREAM_MESSAGE_ID,
} from "@/lib/lighthouse/analyst-stream";
import { authContextStorage } from "@/lib/lighthouse/auth-context";
import { getCurrentDataSection } from "@/lib/lighthouse/data";
import { convertVercelMessageToLangChainMessage } from "@/lib/lighthouse/utils";
import {
  initLighthouseWorkflow,
  type RuntimeConfig,
} from "@/lib/lighthouse/workflow";
import { SentryErrorSource, SentryErrorType } from "@/sentry";

export async function POST(req: Request) {
  try {
    const {
      messages,
      model,
      provider,
    }: {
      messages: UIMessage[];
      model?: string;
      provider?: string;
    } = await req.json();

    if (!messages) {
      return Response.json({ error: "No messages provided" }, { status: 400 });
    }

    const session = await auth();
    if (!session?.accessToken) {
      return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    const accessToken = session.accessToken;

    return await authContextStorage.run(accessToken, async () => {
      // Get AI configuration to access business context
      const tenantConfigResult = await getTenantConfig();
      const businessContext =
        tenantConfigResult?.data?.attributes?.business_context;

      // Get current user data
      const currentData = await getCurrentDataSection();

      // Pass context to workflow instead of injecting as assistant messages
      const runtimeConfig: RuntimeConfig = {
        model,
        provider,
        businessContext,
        currentData,
      };

      const app = await initLighthouseWorkflow(runtimeConfig);

      // Use streamEvents to get token-by-token streaming + tool events
      const agentStream = app.streamEvents(
        {
          messages: messages
            .filter(
              (message: UIMessage) =>
                message.role === "user" || message.role === "assistant",
            )
            .map(convertVercelMessageToLangChainMessage),
        },
        {
          version: "v2",
        },
      );

      // Custom stream transformer that handles both text and tool events
      const stream = new ReadableStream({
        async start(controller) {
          let hasStarted = false;

          try {
            // Emit text-start at the beginning
            controller.enqueue(createTextStartEvent(STREAM_MESSAGE_ID));

            for await (const streamEvent of agentStream) {
              const { event, data, tags, name } = streamEvent;

              // Stream model tokens (smooth text streaming)
              if (event === "on_chat_model_stream") {
                const wasHandled = handleChatModelStreamEvent(
                  controller,
                  data,
                  tags,
                );
                if (wasHandled) {
                  hasStarted = true;
                }
              }
              // Model finished - check for tool calls
              else if (event === "on_chat_model_end") {
                handleChatModelEndEvent(controller, data);
              }
              // Tool execution started
              else if (event === "on_tool_start") {
                handleToolEvent(
                  controller,
                  CHAIN_OF_THOUGHT_ACTIONS.START,
                  name,
                  data?.input,
                );
              }
              // Tool execution completed
              else if (event === "on_tool_end") {
                handleToolEvent(
                  controller,
                  CHAIN_OF_THOUGHT_ACTIONS.COMPLETE,
                  name,
                  data?.input,
                );
              }
            }

            // Emit text-end at the end
            controller.enqueue(createTextEndEvent(STREAM_MESSAGE_ID));

            controller.close();
          } catch (error) {
            const errorMessage =
              error instanceof Error ? error.message : String(error);

            // Capture stream processing errors
            Sentry.captureException(error, {
              tags: {
                api_route: "lighthouse_analyst",
                error_type: SentryErrorType.STREAM_PROCESSING,
                error_source: SentryErrorSource.API_ROUTE,
              },
              level: "error",
              contexts: {
                lighthouse: {
                  event_type: "stream_error",
                  message_count: messages.length,
                },
              },
            });

            // Emit error as text with consistent prefix
            // Use consistent ERROR_PREFIX for both scenarios so client can detect errors
            if (hasStarted) {
              controller.enqueue(
                createTextDeltaEvent(
                  STREAM_MESSAGE_ID,
                  `\n\n${ERROR_PREFIX} ${errorMessage}`,
                ),
              );
            } else {
              controller.enqueue(
                createTextDeltaEvent(
                  STREAM_MESSAGE_ID,
                  `${ERROR_PREFIX} ${errorMessage}`,
                ),
              );
            }

            controller.enqueue(createTextEndEvent(STREAM_MESSAGE_ID));

            controller.close();
          }
        },
      });

      return createUIMessageStreamResponse({ stream });
    });
  } catch (error) {
    console.error("Error in POST request:", error);

    // Capture API route errors
    Sentry.captureException(error, {
      tags: {
        api_route: "lighthouse_analyst",
        error_type: SentryErrorType.REQUEST_PROCESSING,
        error_source: SentryErrorSource.API_ROUTE,
        method: "POST",
      },
      level: "error",
      contexts: {
        request: {
          method: req.method,
          url: req.url,
          headers: Object.fromEntries(req.headers.entries()),
        },
      },
    });

    return Response.json({ error: getErrorMessage(error) }, { status: 500 });
  }
}
