import { toUIMessageStream } from "@ai-sdk/langchain";
import { createUIMessageStreamResponse, UIMessage } from "ai";

import { getLighthouseConfig } from "@/actions/lighthouse/lighthouse";
import { getErrorMessage } from "@/lib/helper";
import { getCurrentDataSection } from "@/lib/lighthouse/data";
import { convertVercelMessageToLangChainMessage } from "@/lib/lighthouse/utils";
import { initLighthouseWorkflow } from "@/lib/lighthouse/workflow";

export async function POST(req: Request) {
  try {
    const {
      messages,
    }: {
      messages: UIMessage[];
    } = await req.json();

    if (!messages) {
      return Response.json({ error: "No messages provided" }, { status: 400 });
    }

    // Create a new array for processed messages
    const processedMessages = [...messages];

    // Get AI configuration to access business context
    const lighthouseConfig = await getLighthouseConfig();
    const businessContext = lighthouseConfig.business_context;

    // Get current user data
    const currentData = await getCurrentDataSection();

    // Add context messages at the beginning
    const contextMessages: UIMessage[] = [];

    // Add business context if available
    if (businessContext) {
      contextMessages.push({
        id: "business-context",
        role: "assistant",
        parts: [
          {
            type: "text",
            text: `Business Context Information:\n${businessContext}`,
          },
        ],
      });
    }

    // Add current data if available
    if (currentData) {
      contextMessages.push({
        id: "current-data",
        role: "assistant",
        parts: [
          {
            type: "text",
            text: currentData,
          },
        ],
      });
    }

    // Insert all context messages at the beginning
    processedMessages.unshift(...contextMessages);

    const app = await initLighthouseWorkflow();

    const agentStream = app.streamEvents(
      {
        messages: processedMessages
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
              if (data.chunk.content && !!tags && tags.includes("supervisor")) {
                // Pass the raw LangChain stream event - toUIMessageStream will handle conversion
                controller.enqueue(streamEvent);
              }
            }
          }
          controller.close();
        } catch (error) {
          const errorMessage =
            error instanceof Error ? error.message : String(error);
          // For errors, send a plain string that toUIMessageStream will convert to text chunks
          controller.enqueue(`[LIGHTHOUSE_ANALYST_ERROR]: ${errorMessage}`);
          controller.close();
        }
      },
    });

    // Convert LangChain stream to UI message stream and return as SSE response
    return createUIMessageStreamResponse({
      stream: toUIMessageStream(stream),
    });
  } catch (error) {
    console.error("Error in POST request:", error);
    return Response.json(
      { error: await getErrorMessage(error) },
      { status: 500 },
    );
  }
}
