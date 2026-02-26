// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - MCP Types
// JSON-RPC 2.0 message types and MCP protocol schema definitions
// ═══════════════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────────────
// JSON-RPC 2.0 Base Types
// ─────────────────────────────────────────────────────────────────────────────

export interface JSONRPCRequest {
  jsonrpc: '2.0';
  id: string | number;
  method: string;
  params?: unknown;
}

export interface JSONRPCNotification {
  jsonrpc: '2.0';
  method: string;
  params?: unknown;
  // NOTE: intentionally no `id` — this distinguishes notifications from requests/responses
}

export interface JSONRPCResponse {
  jsonrpc: '2.0';
  id: string | number;
  result?: unknown;
  error?: JSONRPCError;
}

export interface JSONRPCError {
  code: number;
  message: string;
  data?: unknown;
}

/** Standard JSON-RPC 2.0 error codes */
export const JSONRPC_ERRORS = {
  PARSE_ERROR:      -32700,
  INVALID_REQUEST:  -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS:   -32602,
  INTERNAL_ERROR:   -32603,
} as const;

// ─────────────────────────────────────────────────────────────────────────────
// MCP Schema (subset of JSON Schema used in tool definitions)
// ─────────────────────────────────────────────────────────────────────────────

export interface MCPSchemaProperty {
  type: string | string[];
  description?: string;
  enum?: unknown[];
  default?: unknown;
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  items?: MCPSchemaProperty;
  properties?: Record<string, MCPSchemaProperty>;
  required?: string[];
}

export interface MCPSchema {
  type: string;
  properties?: Record<string, MCPSchemaProperty>;
  required?: string[];
  description?: string;
  additionalProperties?: boolean | MCPSchemaProperty;
}

// ─────────────────────────────────────────────────────────────────────────────
// MCP Core Entities
// ─────────────────────────────────────────────────────────────────────────────

export interface MCPTool {
  name: string;
  description: string;
  inputSchema: MCPSchema;
}

export interface MCPResource {
  uri: string;
  name: string;
  description?: string;
  mimeType?: string;
}

export interface MCPPromptArgument {
  name: string;
  description?: string;
  required?: boolean;
}

export interface MCPPrompt {
  name: string;
  description?: string;
  arguments?: MCPPromptArgument[];
}

// ─────────────────────────────────────────────────────────────────────────────
// MCP Capability Negotiation
// ─────────────────────────────────────────────────────────────────────────────

export interface MCPServerCapabilities {
  tools?:     { listChanged?: boolean };
  resources?: { listChanged?: boolean; subscribe?: boolean };
  prompts?:   { listChanged?: boolean };
  logging?:   Record<string, unknown>;
  experimental?: Record<string, unknown>;
}

export interface MCPClientCapabilities {
  roots?:    { listChanged?: boolean };
  sampling?: Record<string, unknown>;
  experimental?: Record<string, unknown>;
}

export interface MCPImplementation {
  name: string;
  version: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// MCP Initialize
// ─────────────────────────────────────────────────────────────────────────────

export interface MCPInitializeParams {
  protocolVersion: string;
  capabilities: MCPClientCapabilities;
  clientInfo: MCPImplementation;
}

export interface MCPInitializeResult {
  protocolVersion: string;
  capabilities: MCPServerCapabilities;
  serverInfo: MCPImplementation;
  instructions?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// MCP Tool Operations
// ─────────────────────────────────────────────────────────────────────────────

export interface MCPToolCallParams {
  name: string;
  arguments?: Record<string, unknown>;
}

export interface MCPToolContent {
  type: 'text' | 'image' | 'resource';
  text?: string;         // for type === 'text'
  data?: string;         // base64, for type === 'image'
  mimeType?: string;     // for type === 'image' | 'resource'
  resource?: {
    uri: string;
    text?: string;
    blob?: string;
  };
}

export interface MCPToolCallResult {
  content: MCPToolContent[];
  isError?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// MCP Resource Operations
// ─────────────────────────────────────────────────────────────────────────────

export interface MCPResourceContent {
  uri: string;
  mimeType?: string;
  text?: string;
  blob?: string;
}

export interface MCPReadResourceResult {
  contents: MCPResourceContent[];
}

// ─────────────────────────────────────────────────────────────────────────────
// MCP Client Status
// ─────────────────────────────────────────────────────────────────────────────

export type MCPClientStatus =
  | 'disconnected'
  | 'connecting'
  | 'initializing'
  | 'ready'
  | 'error'
  | 'reconnecting';

/** Current MCP protocol version implemented */
export const MCP_PROTOCOL_VERSION = '2024-11-05';
