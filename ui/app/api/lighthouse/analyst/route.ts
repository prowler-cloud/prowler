import { toUIMessageStream } from "@ai-sdk/langchain";
import * as Sentry from "@sentry/nextjs";
import { createUIMessageStreamResponse, UIMessage } from "ai";

import { getTenantConfig } from "@/actions/lighthouse/lighthouse";
import { auth } from "@/auth.config";
import { getErrorMessage } from "@/lib/helper";
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
          streamMode: ["values", "messages", "custom"],
          version: "v2",
        },
      );

      const stream = new ReadableStream({
        async start(controller) {
          try {
            for await (const streamEvent of agentStream) {
              const { event, data, tags } = streamEvent;
              if (event === "on_chat_model_stream") {
                if (
                  data.chunk.content &&
                  !!tags &&
                  tags.includes("lighthouse-agent")
                ) {
                  controller.enqueue(streamEvent);
                }
              }
            }
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

            controller.enqueue(`[LIGHTHOUSE_ANALYST_ERROR]: ${errorMessage}`);
            controller.close();
          }
        },
      });

      return createUIMessageStreamResponse({
        stream: toUIMessageStream(stream),
      });
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
