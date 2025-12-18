/**
 * Enum for standardized error types across the application
 */
export enum SentryErrorType {
  // API Errors
  API_ERROR = "api_error",
  SERVER_ERROR = "server_error",
  CLIENT_ERROR = "client_error",

  // Request Processing
  REQUEST_PROCESSING = "request_processing",
  STREAM_PROCESSING = "stream_processing",

  // Application Errors
  APPLICATION_ERROR = "application_error",
  UNEXPECTED_ERROR = "unexpected_error",
  NON_ERROR_OBJECT = "non_error_object",

  // Authentication
  AUTH_ERROR = "auth_error",
  PERMISSION_ERROR = "permission_error",

  // Server Actions
  SERVER_ACTION_ERROR = "server_action_error",

  // MCP Client
  MCP_CONNECTION_ERROR = "mcp_connection_error",
  MCP_DISCOVERY_ERROR = "mcp_discovery_error",
}

/**
 * Enum for error sources
 */
export enum SentryErrorSource {
  ERROR_BOUNDARY = "error_boundary",
  API_ROUTE = "api_route",
  SERVER_ACTION = "server_action",
  HANDLE_API_ERROR = "handleApiError",
  HANDLE_API_RESPONSE = "handleApiResponse",
  MCP_CLIENT = "mcp_client",
}
