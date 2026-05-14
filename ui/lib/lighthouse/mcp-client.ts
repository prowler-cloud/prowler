import "server-only";

import type { StructuredTool } from "@langchain/core/tools";
import { MultiServerMCPClient } from "@langchain/mcp-adapters";
import {
  addBreadcrumb,
  captureException,
  captureMessage,
} from "@sentry/nextjs";

import { getAuthContext } from "@/lib/lighthouse/auth-context";
import { SentryErrorSource, SentryErrorType } from "@/sentry";

/** Maximum number of retry attempts for MCP connection */
const MAX_RETRY_ATTEMPTS = 3;

/** Delay between retry attempts in milliseconds */
const RETRY_DELAY_MS = 2000;

/** Time after which to attempt reconnection if MCP is unavailable (5 minutes) */
const RECONNECT_INTERVAL_MS = 5 * 60 * 1000;

/**
 * Delays execution for specified milliseconds
 */
function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * MCP Client State
 * Using a class-based singleton for better encapsulation and testability
 */
class MCPClientManager {
  private client: MultiServerMCPClient | null = null;
  private tools: StructuredTool[] = [];
  private available = false;
  private initializationAttempted = false;
  private initializationPromise: Promise<void> | null = null;
  private lastAttemptTime: number | null = null;

  /**
   * Validates the MCP server URL from environment variables
   */
  private validateMCPServerUrl(): string | null {
    const mcpServerUrl = process.env.PROWLER_MCP_SERVER_URL;

    if (!mcpServerUrl) {
      // MCP is optional - not an error if not configured
      return null;
    }

    try {
      new URL(mcpServerUrl);
      return mcpServerUrl;
    } catch {
      captureMessage(`Invalid PROWLER_MCP_SERVER_URL: ${mcpServerUrl}`, {
        level: "error",
        tags: {
          error_source: SentryErrorSource.MCP_CLIENT,
          error_type: SentryErrorType.MCP_CONNECTION_ERROR,
        },
      });
      return null;
    }
  }

  /**
   * Checks if enough time has passed to allow a reconnection attempt
   */
  private shouldAttemptReconnection(): boolean {
    if (!this.lastAttemptTime) return true;
    if (this.available) return false;

    const timeSinceLastAttempt = Date.now() - this.lastAttemptTime;
    return timeSinceLastAttempt >= RECONNECT_INTERVAL_MS;
  }

  /**
   * Injects auth headers for Prowler App tools
   */
  private handleBeforeToolCall = ({
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
      addBreadcrumb({
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
  };

  /**
   * Attempts to connect to the MCP server with retry logic
   */
  private async connectWithRetry(mcpServerUrl: string): Promise<boolean> {
    for (let attempt = 1; attempt <= MAX_RETRY_ATTEMPTS; attempt++) {
      try {
        this.client = new MultiServerMCPClient({
          additionalToolNamePrefix: "",
          mcpServers: {
            prowler: {
              transport: "http",
              url: mcpServerUrl,
              defaultToolTimeout: 180000, // 3 minutes
            },
          },
          beforeToolCall: this.handleBeforeToolCall,
        });

        this.tools = await this.client.getTools();
        this.available = true;

        addBreadcrumb({
          category: "mcp-client",
          message: `MCP client connected successfully (attempt ${attempt})`,
          level: "info",
          data: { toolCount: this.tools.length },
        });

        return true;
      } catch (error) {
        const isLastAttempt = attempt === MAX_RETRY_ATTEMPTS;
        const errorMessage =
          error instanceof Error ? error.message : String(error);

        addBreadcrumb({
          category: "mcp-client",
          message: `MCP connection attempt ${attempt}/${MAX_RETRY_ATTEMPTS} failed`,
          level: "warning",
          data: { error: errorMessage },
        });

        if (isLastAttempt) {
          const isConnectionError =
            errorMessage.includes("ECONNREFUSED") ||
            errorMessage.includes("ENOTFOUND") ||
            errorMessage.includes("timeout") ||
            errorMessage.includes("network");

          captureException(error, {
            tags: {
              error_type: isConnectionError
                ? SentryErrorType.MCP_CONNECTION_ERROR
                : SentryErrorType.MCP_DISCOVERY_ERROR,
              error_source: SentryErrorSource.MCP_CLIENT,
            },
            level: "error",
            contexts: {
              mcp: {
                server_url: mcpServerUrl,
                attempts: MAX_RETRY_ATTEMPTS,
                error_message: errorMessage,
                is_connection_error: isConnectionError,
              },
            },
          });

          console.error(`[MCP Client] Failed to initialize: ${errorMessage}`);
        } else {
          await delay(RETRY_DELAY_MS);
        }
      }
    }

    return false;
  }

  async initialize(): Promise<void> {
    // Return if already initialized and available
    if (this.available) {
      return;
    }

    // If initialization in progress, wait for it
    if (this.initializationPromise) {
      return this.initializationPromise;
    }

    // Check if we should attempt reconnection (rate limiting)
    if (this.initializationAttempted && !this.shouldAttemptReconnection()) {
      return;
    }

    this.initializationPromise = this.performInitialization();

    try {
      await this.initializationPromise;
    } finally {
      this.initializationPromise = null;
    }
  }

  private async performInitialization(): Promise<void> {
    this.initializationAttempted = true;
    this.lastAttemptTime = Date.now();

    // Validate URL before attempting connection
    const mcpServerUrl = this.validateMCPServerUrl();
    if (!mcpServerUrl) {
      this.available = false;
      this.client = null;
      this.tools = [];
      return;
    }

    // Attempt connection with retry logic
    const connected = await this.connectWithRetry(mcpServerUrl);

    if (!connected) {
      this.available = false;
      this.client = null;
      this.tools = [];
    }
  }

  getTools(): StructuredTool[] {
    return this.tools;
  }

  getToolsByPattern(pattern: RegExp): StructuredTool[] {
    return this.tools.filter((tool) => pattern.test(tool.name));
  }

  getToolByName(name: string): StructuredTool | undefined {
    return this.tools.find((tool) => tool.name === name);
  }

  getToolsByNames(names: string[]): StructuredTool[] {
    return this.tools.filter((tool) => names.includes(tool.name));
  }

  isAvailable(): boolean {
    return this.available;
  }

  /**
   * Gets detailed status of the MCP connection
   * Useful for debugging and health monitoring
   */
  getConnectionStatus(): {
    available: boolean;
    toolCount: number;
    lastAttemptTime: number | null;
    initializationAttempted: boolean;
    canRetry: boolean;
  } {
    return {
      available: this.available,
      toolCount: this.tools.length,
      lastAttemptTime: this.lastAttemptTime,
      initializationAttempted: this.initializationAttempted,
      canRetry: this.shouldAttemptReconnection(),
    };
  }

  /**
   * Forces a reconnection attempt to the MCP server
   * Useful when the server has been restarted or connection was lost
   */
  async reconnect(): Promise<boolean> {
    // Reset state to allow reconnection
    this.available = false;
    this.initializationAttempted = false;
    this.lastAttemptTime = null;

    // Attempt to initialize
    await this.initialize();

    return this.available;
  }

  reset(): void {
    this.client = null;
    this.tools = [];
    this.available = false;
    this.initializationAttempted = false;
    this.initializationPromise = null;
    this.lastAttemptTime = null;
  }
}

// Singleton instance using global for HMR support in development
const globalForMCP = global as typeof global & {
  mcpClientManager?: MCPClientManager;
};

function getManager(): MCPClientManager {
  if (!globalForMCP.mcpClientManager) {
    globalForMCP.mcpClientManager = new MCPClientManager();
  }
  return globalForMCP.mcpClientManager;
}

// Public API - maintains backwards compatibility
export async function initializeMCPClient(): Promise<void> {
  return getManager().initialize();
}

export function getMCPTools(): StructuredTool[] {
  return getManager().getTools();
}

export function getMCPToolsByPattern(namePattern: RegExp): StructuredTool[] {
  return getManager().getToolsByPattern(namePattern);
}

export function getMCPToolByName(name: string): StructuredTool | undefined {
  return getManager().getToolByName(name);
}

export function getMCPToolsByNames(names: string[]): StructuredTool[] {
  return getManager().getToolsByNames(names);
}

export function isMCPAvailable(): boolean {
  return getManager().isAvailable();
}

export function getMCPConnectionStatus(): {
  available: boolean;
  toolCount: number;
  lastAttemptTime: number | null;
  initializationAttempted: boolean;
  canRetry: boolean;
} {
  return getManager().getConnectionStatus();
}

export async function reconnectMCPClient(): Promise<boolean> {
  return getManager().reconnect();
}

export function resetMCPClient(): void {
  getManager().reset();
}
