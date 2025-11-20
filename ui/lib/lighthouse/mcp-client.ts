import type { StructuredTool } from "@langchain/core/tools";
import { MultiServerMCPClient } from "@langchain/mcp-adapters";

import { getAuthContext } from "@/lib/lighthouse/auth-context";

interface GlobalMCPClient {
  mcpClient: MultiServerMCPClient | null;
  mcpTools: StructuredTool[];
  mcpAvailable: boolean;
  initializationAttempted: boolean;
  initializationPromise: Promise<void> | null;
}

const globalForMCP = global as typeof global & {
  mcp?: GlobalMCPClient;
};

if (!globalForMCP.mcp) {
  globalForMCP.mcp = {
    mcpClient: null,
    mcpTools: [],
    mcpAvailable: false,
    initializationAttempted: false,
    initializationPromise: null,
  };
}

const mcpState = globalForMCP.mcp;

export async function initializeMCPClient(): Promise<void> {
  if (mcpState.initializationAttempted && mcpState.mcpAvailable) {
    // Return if MCP Client already initialized
    return;
  }

  if (mcpState.initializationPromise) {
    // If initialization in progress, return promise
    return mcpState.initializationPromise;
  }

  mcpState.initializationPromise = (async () => {
    mcpState.initializationAttempted = true;

    try {
      const mcpServerUrl = process.env.PROWLER_MCP_SERVER_URL || "";

      mcpState.mcpClient = new MultiServerMCPClient({
        additionalToolNamePrefix: "",
        mcpServers: {
          prowler: {
            transport: "http",
            url: mcpServerUrl,
          },
        },
        beforeToolCall: ({
          name,
          args,
        }: {
          serverName: string;
          name: string;
          args?: unknown;
        }) => {
          // Only inject auth for Prowler App tool
          if (!name.startsWith("prowler_app_")) {
            return { args };
          }

          const accessToken = getAuthContext();
          if (!accessToken) {
            return { args };
          }

          return {
            args,
            headers: {
              Authorization: `Bearer ${accessToken}`,
            },
          };
        },
      });

      mcpState.mcpTools = await mcpState.mcpClient.getTools();
      mcpState.mcpAvailable = true;
    } catch (error) {
      console.error("[MCP Client] Failed to initialize MCP client:", error);
      mcpState.mcpAvailable = false;
      mcpState.mcpClient = null;
      mcpState.mcpTools = [];
    } finally {
      mcpState.initializationPromise = null;
    }
  })();

  return mcpState.initializationPromise;
}

export function getMCPTools(): StructuredTool[] {
  return mcpState.mcpTools;
}

export function getMCPToolsByPattern(namePattern: RegExp): StructuredTool[] {
  return mcpState.mcpTools.filter((tool) => namePattern.test(tool.name));
}

export function getMCPToolByName(name: string): StructuredTool | undefined {
  return mcpState.mcpTools.find((tool) => tool.name === name);
}

export function getMCPToolsByNames(names: string[]): StructuredTool[] {
  return mcpState.mcpTools.filter((tool) => names.includes(tool.name));
}

export function isMCPAvailable(): boolean {
  return mcpState.mcpAvailable;
}

export function resetMCPClient(): void {
  mcpState.mcpClient = null;
  mcpState.mcpTools = [];
  mcpState.mcpAvailable = false;
  mcpState.initializationAttempted = false;
  mcpState.initializationPromise = null;
}
