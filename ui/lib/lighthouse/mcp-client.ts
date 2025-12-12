import "server-only";

import type { StructuredTool } from "@langchain/core/tools";
import { MultiServerMCPClient } from "@langchain/mcp-adapters";
import * as Sentry from "@sentry/nextjs";

import { getAuthContext } from "@/lib/lighthouse/auth-context";

/** Maximum number of retry attempts for MCP connection */
const MAX_RETRY_ATTEMPTS = 3;

/** Delay between retry attempts in milliseconds */
const RETRY_DELAY_MS = 2000;

/** Time after which to attempt reconnection if MCP is unavailable (5 minutes) */
const RECONNECT_INTERVAL_MS = 5 * 60 * 1000;

interface GlobalMCPClient {
  mcpClient: MultiServerMCPClient | null;
  mcpTools: StructuredTool[];
  mcpAvailable: boolean;
  initializationAttempted: boolean;
  initializationPromise: Promise<void> | null;
  lastAttemptTime: number | null;
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
    lastAttemptTime: null,
  };
}

const mcpState = globalForMCP.mcp;

/**
 * Validates the MCP server URL from environment variables
 * @returns The validated URL or null if invalid/missing
 */
function validateMCPServerUrl(): string | null {
  const mcpServerUrl = process.env.PROWLER_MCP_SERVER_URL;

  if (!mcpServerUrl) {
    Sentry.captureMessage(
      "PROWLER_MCP_SERVER_URL environment variable is not set",
      {
        level: "warning",
        tags: { component: "mcp-client" },
      },
    );
    return null;
  }

  try {
    new URL(mcpServerUrl);
    return mcpServerUrl;
  } catch {
    Sentry.captureMessage(`Invalid PROWLER_MCP_SERVER_URL: ${mcpServerUrl}`, {
      level: "error",
      tags: { component: "mcp-client" },
    });
    return null;
  }
}

/**
 * Delays execution for specified milliseconds
 */
function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Checks if enough time has passed to allow a reconnection attempt
 */
function shouldAttemptReconnection(): boolean {
  if (!mcpState.lastAttemptTime) return true;
  if (mcpState.mcpAvailable) return false;

  const timeSinceLastAttempt = Date.now() - mcpState.lastAttemptTime;
  return timeSinceLastAttempt >= RECONNECT_INTERVAL_MS;
}

/**
 * Attempts to connect to the MCP server with retry logic
 */
async function connectWithRetry(mcpServerUrl: string): Promise<boolean> {
  for (let attempt = 1; attempt <= MAX_RETRY_ATTEMPTS; attempt++) {
    try {
      mcpState.mcpClient = new MultiServerMCPClient({
        additionalToolNamePrefix: "",
        mcpServers: {
          prowler: {
            // Use HTTP transport for MCP server communication
            // See: https://github.com/langchain-ai/langchain-mcp-adapters
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
          // Only inject auth for Prowler App tools (user-specific data)
          // Prowler Hub and Prowler Docs tools don't require authentication
          if (!name.startsWith("prowler_app_")) {
            return { args };
          }

          const accessToken = getAuthContext();
          if (!accessToken) {
            Sentry.addBreadcrumb({
              category: "mcp-client",
              message: `Auth context missing for tool: ${name}`,
              level: "warning",
            });
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

      Sentry.addBreadcrumb({
        category: "mcp-client",
        message: `MCP client connected successfully (attempt ${attempt})`,
        level: "info",
        data: { toolCount: mcpState.mcpTools.length },
      });

      return true;
    } catch (error) {
      const isLastAttempt = attempt === MAX_RETRY_ATTEMPTS;

      Sentry.addBreadcrumb({
        category: "mcp-client",
        message: `MCP connection attempt ${attempt}/${MAX_RETRY_ATTEMPTS} failed`,
        level: "warning",
        data: { error: error instanceof Error ? error.message : String(error) },
      });

      if (isLastAttempt) {
        Sentry.captureException(error, {
          tags: {
            component: "mcp-client",
            error_type: "connection_failed",
          },
          level: "error",
          contexts: {
            mcp: {
              server_url: mcpServerUrl,
              attempts: MAX_RETRY_ATTEMPTS,
            },
          },
        });
      } else {
        await delay(RETRY_DELAY_MS);
      }
    }
  }

  return false;
}

export async function initializeMCPClient(): Promise<void> {
  // Return if already initialized and available
  if (mcpState.mcpAvailable) {
    return;
  }

  // If initialization in progress, wait for it
  if (mcpState.initializationPromise) {
    return mcpState.initializationPromise;
  }

  // Check if we should attempt reconnection (rate limiting)
  if (mcpState.initializationAttempted && !shouldAttemptReconnection()) {
    return;
  }

  mcpState.initializationPromise = (async () => {
    mcpState.initializationAttempted = true;
    mcpState.lastAttemptTime = Date.now();

    // Validate URL before attempting connection
    const mcpServerUrl = validateMCPServerUrl();
    if (!mcpServerUrl) {
      mcpState.mcpAvailable = false;
      mcpState.mcpClient = null;
      mcpState.mcpTools = [];
      return;
    }

    // Attempt connection with retry logic
    const connected = await connectWithRetry(mcpServerUrl);

    if (!connected) {
      mcpState.mcpAvailable = false;
      mcpState.mcpClient = null;
      mcpState.mcpTools = [];
    }
  })();

  try {
    await mcpState.initializationPromise;
  } finally {
    mcpState.initializationPromise = null;
  }
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

/**
 * Gets detailed status of the MCP connection
 * Useful for debugging and health monitoring
 */
export function getMCPConnectionStatus(): {
  available: boolean;
  toolCount: number;
  lastAttemptTime: number | null;
  initializationAttempted: boolean;
  canRetry: boolean;
} {
  return {
    available: mcpState.mcpAvailable,
    toolCount: mcpState.mcpTools.length,
    lastAttemptTime: mcpState.lastAttemptTime,
    initializationAttempted: mcpState.initializationAttempted,
    canRetry: shouldAttemptReconnection(),
  };
}

/**
 * Forces a reconnection attempt to the MCP server
 * Useful when the server has been restarted or connection was lost
 */
export async function reconnectMCPClient(): Promise<boolean> {
  // Reset state to allow reconnection
  mcpState.mcpAvailable = false;
  mcpState.initializationAttempted = false;
  mcpState.lastAttemptTime = null;

  // Attempt to initialize
  await initializeMCPClient();

  return mcpState.mcpAvailable;
}

export function resetMCPClient(): void {
  mcpState.mcpClient = null;
  mcpState.mcpTools = [];
  mcpState.mcpAvailable = false;
  mcpState.initializationAttempted = false;
  mcpState.initializationPromise = null;
  mcpState.lastAttemptTime = null;
}
