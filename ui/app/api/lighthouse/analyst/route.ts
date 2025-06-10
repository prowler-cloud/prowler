import { LangChainAdapter, Message } from "ai";

import { getLighthouseConfig } from "@/actions/lighthouse/lighthouse";
import { getCurrentDataSection } from "@/lib/lighthouse/data";
import {
  convertLangChainMessageToVercelMessage,
  convertVercelMessageToLangChainMessage,
} from "@/lib/lighthouse/utils";
import { initLighthouseWorkflow } from "@/lib/lighthouse/workflow";

export async function POST(req: Request) {
  try {
    const {
      messages,
    }: {
      messages: Message[];
    } = await req.json();

    if (!messages) {
      return Response.json({ error: "No messages provided" }, { status: 400 });
    }

    // Create a new array for processed messages
    const processedMessages = [...messages];

    // Get AI configuration to access business context
    const aiConfig = await getLighthouseConfig();
    const businessContext = aiConfig?.data?.attributes?.business_context;

    // Get current user data
    const currentData = await getCurrentDataSection();

    // Add context messages at the beginning
    const contextMessages: Message[] = [];

    // Add business context if available
    if (businessContext) {
      contextMessages.push({
        id: "business-context",
        role: "assistant",
        content: `Business Context Information:\n${businessContext}`,
      });
    }

    // Add current data if available
    if (currentData) {
      contextMessages.push({
        id: "current-data",
        role: "assistant",
        content: currentData,
      });
    }

    // Insert all context messages at the beginning
    processedMessages.unshift(...contextMessages);

    const app = await initLighthouseWorkflow();

    const agentStream = app.streamEvents(
      {
        messages: processedMessages
          .filter(
            (message: Message) =>
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
        for await (const { event, data, tags } of agentStream) {
          if (event === "on_chat_model_stream") {
            if (data.chunk.content && !!tags && tags.includes("supervisor")) {
              const chunk = data.chunk;
              const aiMessage = convertLangChainMessageToVercelMessage(chunk);
              controller.enqueue(aiMessage);
            }
          }
        }
        controller.close();
      },
    });

    return LangChainAdapter.toDataStreamResponse(stream);
  } catch (error) {
    console.error("Error in POST request:", error);
    return Response.json({ error: "An error occurred" }, { status: 500 });
  }
}
