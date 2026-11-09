export type Transport = "stdio" | "sse" | "streamable-http" | "unknown";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Evidence {
  kind: "config_file" | "process" | "listen_port" | "capability_probe";
  source: string;
  observed_at: string;
  detail: Record<string, unknown>;
}

export interface ScanError {
  code: string;
  message: string;
  source: string | null;
}

export interface ProcessMatch {
  pid: number;
  name: string;
  cmdline: string[];
  username: string | null;
  create_time: number | null;
  confidence: number;
  reason: string;
}

export interface ListenCheck {
  host: string;
  port: number;
  listening: boolean;
  pids: number[];
}

export interface ToolSpec {
  name: string;
  description: string;
  input_schema: Record<string, unknown>;
}

export interface CapabilitySnapshot {
  protocol_version: string | null;
  server_name: string | null;
  server_version: string | null;
  tools: ToolSpec[];
  ok: boolean;
  error: string | null;
}

export interface RiskFlag {
  rule_id: string;
  severity: Severity;
  title: string;
  explanation: string;
  evidence: string[];
}

export interface ServerRecord {
  id: string;
  name: string;
  client: string;
  transport: Transport;
  command: string | null;
  args: string[];
  env_keys: string[];
  url: string | null;
  cwd: string | null;
  config_path: string;
  processes: ProcessMatch[];
  listen: ListenCheck | null;
  capabilities: CapabilitySnapshot | null;
  risk_flags: RiskFlag[];
  evidence: Evidence[];
  container: ContainerMatch | null;
  tls: TlsObservation | null;
  auth: AuthObservation | null;
  merged_from: string[];
}

export interface Coverage {
  clients_requested: string[];
  config_paths_checked: string[];
  config_paths_found: string[];
  project_roots: string[];
  introspect_enabled: boolean;
  limitations: string[];
}

export interface Inventory {
  schema_version: string;
  tool_version: string;
  scanned_at: string;
  host: { os: string; hostname: string };
  servers: ServerRecord[];
  errors: ScanError[];
  coverage: Coverage;
}



export interface ContainerMatch {
  container_id: string;
  name: string;
  image: string;
  status: string;
  ports: string[];
  env_keys: string[];
  command: string[];
}

export interface TlsObservation {
  scheme: string;
  subject: string | null;
  issuer: string | null;
  not_after: string | null;
  error: string | null;
}

export interface AuthObservation {
  required: boolean | null;
  status: number | null;
  www_authenticate_schemes: string[];
  error: string | null;
}