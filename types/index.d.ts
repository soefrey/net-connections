/**
 * `share`: file access over a UNC path (SMB/WebDAV), network traffic but no API or web request.
 * `local`: a tool call with no known network access, kept so every prompt's calls are complete. */
export type NetKind = 'model' | 'web' | 'shell' | 'mcp' | 'service' | 'share' | 'local'

export type NetStatus = 'running' | 'ok' | 'error' | 'denied'

export type NetDetail = { key: string; value: string }

export type NetConn = {
  id: string
  seq: number
  kind: NetKind
  /** The tool that made it (`WebFetch`, `Bash`, `mcp__x__y`), or `model`. */
  source: string
  host: string
  url?: string
  protocol: string
  /**
   * `observed`: the engine reported it; `inferred`: read off a command;
   * `uncertain`: the command starts a script or interpreter that may connect;
   * `local`: no known network access.
   */
  confidence: 'observed' | 'inferred' | 'uncertain' | 'local'
  /** Why it counts as a connection (what in the command pointed at the network). */
  reason: string
  startedAt: number
  endedAt?: number
  status: NetStatus
  statusText?: string
  bytes?: number
  promptId?: string
  agentId?: string
  toolUseId?: string
  /** The command or tool input that caused it. */
  command?: string
  /**
   * Set on a connection the poller saw in the TCP table: it belongs to the
   * tool call row with the same `toolUseId`.
   */
  seenByPoller?: true
  details: NetDetail[]
}

export type NetPrompt = {
  id: string
  seq: number
  kind: 'prompt' | 'command' | 'other'
  text: string
  at: number
}

export type NetView = {
  mode: 'list' | 'detail' | 'prompts' | 'hosts'
  selected?: string
  filter: 'all' | NetKind
  promptId?: string
  host?: string
  page: number
  /** Whether lists show `local` tool calls; absent means hidden. */
  showLocal?: boolean
  /** Which response a WebFetch detail shows: the tool's output (default) or the page's raw body. */
  response?: 'tool' | 'raw'
  /** Which part of a raw body the detail shows, from 0. */
  rawPage?: number
  /** The views left by drilling in, latest last: what `b` returns to. */
  back?: NetView[]
}

/**
 * A page's raw body, fetched again by the pane on request: a mod never sees
 * the bytes WebFetch itself received, only the tool's processed output.
 */
export type NetRaw = {
  state: 'loading' | 'ok' | 'error'
  url: string
  /** When the pane's own request started, in clock milliseconds. */
  at: number
  status?: number
  headers?: Record<string, string>
  /** The body as text, cut to the first `RAW_MAX` characters. */
  text?: string
  /** The body's full length in characters, before any cut. */
  length?: number
  error?: string
}

/**
 * A network file system reachable through a local path: a mapped drive on
 * Windows (`Z:` → `\\server\share`), a mount point on macOS and Linux
 * (`/Volumes/share` → `//user@server/share`, smbfs).
 */
export type NetMount = {
  /** `Z:` on Windows; the absolute mount point elsewhere. */
  root: string
  /** What is mounted: the UNC path, `//server/share`, `server:/export`, a URL. */
  source: string
  host: string
  protocol: string
  /** The file system type as `mount` names it (`cifs`, `nfs4`, `smbfs`), or `drive`. */
  fsType: string
}

export type NetMounts = {
  /** `unknown` until the first lookup answered. */
  platform: 'windows' | 'posix' | 'unknown'
  list: NetMount[]
  /** When the list was last read, in clock milliseconds. */
  at: number
  /** Whether any lookup has answered yet; absent means no. */
  isLoaded?: boolean
  /** Why the last lookup failed, when it did. */
  error?: string
}

declare module 'claude-code' {
  interface PluginState {
    'net-connections': {
      conns: NetConn[]
      prompts: NetPrompt[]
      current: string | null
      agents: Record<string, string>
      view: NetView
      /** Network drives and mounts, read at session start and every 10 minutes. */
      mounts: NetMounts
      /** Raw page bodies the pane fetched on request, by connection id. */
      raw: Record<string, NetRaw>
      /** Hosts no earlier session had seen, flagged for this session only. */
      newHosts: string[]
    }
  }
}
