import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register, RenderInput } from 'claude-code'

import type { NetConn, NetDetail, NetKind, NetMount, NetMounts, NetPrompt, NetRaw, NetStatus, NetView } from '../types'
import {
  detectMounts,
  detectShare,
  detectShell,
  detectUncertain,
  driveMounts,
  hostOf,
  parseCimDrives,
  parseMountOutput,
  parseNetUse,
  maskHome,
  PLACEHOLDER_HOSTS,
  protocolOf,
  redact,
} from './detect'
import type { Target } from './detect'
import { POLL_SCRIPT, parsePollLine, portProtocol, shortCommand } from './poller'

const PANE = 'net-connections'
const TITLE = 'Network connections'
const MAX_CONNS = 1000
const MAX_PROMPTS = 300

const conns = atom({ plugin: 'net-connections', key: 'conns' } as const, [])
const prompts = atom({ plugin: 'net-connections', key: 'prompts' } as const, [])
const current = atom({ plugin: 'net-connections', key: 'current' } as const, null)
const agents = atom({ plugin: 'net-connections', key: 'agents' } as const, {})
const view = atom({ plugin: 'net-connections', key: 'view' } as const, { mode: 'list', filter: 'all', page: 0 })
const mounts = atom({ plugin: 'net-connections', key: 'mounts' } as const, { platform: 'unknown', list: [], at: 0 })
const raw = atom({ plugin: 'net-connections', key: 'raw' } as const, {})

// A raw body kept past this is cut; the pane says how much it left out.
const RAW_MAX = 100_000
const MAX_RAW = 20
// A rendered tree holds at most 100,000 characters and a Text at most 10,000,
// so the raw body is drawn a page at a time, in Texts of a few lines each.
const RAW_PAGE = 8_000
const RAW_CHUNK = 2_000

/**
 * Text a tree may hold: newlines for every line break, tab and newline the
 * only control characters, and no bidirectional overrides, which could show
 * a command as other than it ran.
 */
const printable = (s: string) =>
  s.replace(/\r\n?/g, '\n').replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, '\ufffd')

/** What the pane keeps of a string it records: printable, credentials masked, home directories as `~`. */
const clean = (s: string) => maskHome(redact(printable(s)))

const cleanDetails = (ds: readonly NetDetail[]) => ds.map(d => ({ key: clean(d.key), value: clean(d.value) }))

function cleanConn<T extends Partial<NetConn>>(c: T): T {
  const out: Partial<NetConn> = { ...c }
  for (const k of ['source', 'host', 'url', 'reason', 'statusText', 'command'] as const) {
    const v = out[k]
    if (typeof v === 'string') out[k] = clean(v)
  }
  if (out.details) out.details = cleanDetails(out.details)
  return out as T
}

/** Cuts `s` into pieces of at most `n` characters, at a line break where one is near. */
function chunks(s: string, n: number): string[] {
  const out: string[] = []
  let i = 0
  while (i < s.length) {
    let j = Math.min(s.length, i + n)
    if (j < s.length) {
      const nl = s.lastIndexOf('\n', j)
      if (nl > i + n / 2) j = nl + 1
    }
    out.push(s.slice(i, j).replace(/\n$/, ''))
    i = j
  }
  return out
}

const MOUNT_REFRESH_MS = 10 * 60 * 1000
// Locale-independent, unlike `net use`: one `Z:|\\server\share` line per mapped drive.
const CIM_DRIVES = "Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=4' | ForEach-Object { $_.DeviceID + '|' + $_.ProviderName }"

// Tools that talk to claude.ai / Anthropic services rather than the local machine.
const SERVICE_TOOLS = new Set([
  'Artifact', 'ArtifactData', 'ArtifactComments', 'ArtifactCheck', 'DesignSync', 'ClaudeDesign',
  'RemoteTrigger', 'ReadNotifications', 'SendUserFile', 'SendFile', 'FetchInboxMessage',
  'SearchMcpRegistry', 'SearchPlugins', 'SearchSkills', 'SendFeedback', 'Projects',
])
const SHELL_TOOLS = new Set(['Bash', 'PowerShell', 'Monitor'])
// Path arguments a file tool may point at a UNC share through.
const PATH_FIELDS = ['file_path', 'notebook_path', 'path'] as const

const KIND_COLOR: Record<NetKind, string> = {
  model: 'magenta',
  web: 'cyan',
  shell: 'yellow',
  mcp: 'blue',
  service: 'green',
  share: '#ff8700',
  local: 'gray',
}
const KIND_LABEL: Record<NetKind, string> = {
  model: 'MODEL',
  web: 'WEB',
  shell: 'SHELL',
  mcp: 'MCP',
  service: 'SVC',
  share: 'SHARE',
  local: 'LOCAL',
}
// The mark beside a row's status: how sure the pane is that it touched the network.
const EVIDENCE_MARK: Record<NetConn['confidence'], string> = {
  observed: ' ',
  inferred: '~',
  uncertain: '?',
  local: ' ',
}
const EVIDENCE_TEXT: Record<NetConn['confidence'], string> = {
  observed: 'observed by the engine',
  inferred: 'inferred from the command text',
  uncertain: 'uncertain: the command runs code whose connections are not visible',
  local: 'local: no known network access',
}

const STATUS_MARK: Record<NetStatus, { glyph: string; color: string }> = {
  running: { glyph: '…', color: 'yellow' },
  ok: { glyph: '✓', color: 'green' },
  error: { glyph: '✗', color: 'red' },
  denied: { glyph: '⊘', color: 'gray' },
}

type $ = EngineInterface
type Loose = Record<string, unknown>

// ---------- formatting ----------

const pad2 = (n: number) => String(n).padStart(2, '0')
const fmtTime = (ms: number) => {
  const d = new Date(ms)
  return `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`
}
const fmtDur = (ms?: number) =>
  ms === undefined ? '' : ms < 1000 ? `${Math.round(ms)}ms` : ms < 60_000 ? `${(ms / 1000).toFixed(1)}s` : `${Math.floor(ms / 60_000)}m${Math.round((ms % 60_000) / 1000)}s`
const fmtBytes = (b?: number) =>
  b === undefined ? '' : b < 1024 ? `${b}B` : b < 1024 * 1024 ? `${(b / 1024).toFixed(1)}KB` : `${(b / 1024 / 1024).toFixed(1)}MB`
const fmtNum = (n: number) => (n >= 10_000 ? `${(n / 1000).toFixed(1)}k` : String(n))
const oneLine = (s: string) => s.replace(/\s+/g, ' ').trim()
const trunc = (s: string, n: number) => (n <= 1 ? '' : s.length > n ? `${s.slice(0, n - 1)}…` : s)
const durOf = (c: NetConn) => (c.endedAt === undefined ? undefined : c.endedAt - c.startedAt)

// ---------- recording ----------

let idCounter = 0
const mkId = (now: number) => `${now.toString(36)}-${(idCounter++).toString(36)}`

let apiHostCache: string | undefined
async function apiHost($: $): Promise<string> {
  if (apiHostCache !== undefined) return apiHostCache
  const base = await $.env.get('ANTHROPIC_BASE_URL')
  if (base) apiHostCache = hostOf(base)
  else if (await $.env.get('CLAUDE_CODE_USE_BEDROCK')) apiHostCache = `bedrock-runtime.${(await $.env.get('AWS_REGION')) ?? 'us-east-1'}.amazonaws.com`
  else if (await $.env.get('CLAUDE_CODE_USE_VERTEX')) apiHostCache = `${(await $.env.get('CLOUD_ML_REGION')) ?? 'us-east5'}-aiplatform.googleapis.com`
  else apiHostCache = 'api.anthropic.com'
  return apiHostCache
}

async function originFor($: $, agentId: string | undefined): Promise<string | undefined> {
  const cur = (await read($, current)) ?? undefined
  if (agentId === undefined) return cur
  const known = (await read($, agents))[agentId]
  if (known !== undefined) return known
  if (cur !== undefined) await update($, agents, m => (agentId in m ? m : { ...m, [agentId]: cur }))
  return cur
}

async function addConn($: $, c: Omit<NetConn, 'seq'>) {
  const kept = cleanConn(c)
  await update($, conns, list => [...list, { ...kept, seq: (list.at(-1)?.seq ?? 0) + 1 }].slice(-MAX_CONNS))
}

async function patchConn($: $, id: string, p: Partial<NetConn>, more: NetDetail[] = []) {
  const kept = cleanConn(p)
  const added = cleanDetails(more)
  await update($, conns, list =>
    list.map(c => (c.id === id ? { ...c, ...kept, details: [...c.details, ...added] } : c)),
  )
}

async function addPrompt($: $, p: Omit<NetPrompt, 'seq'>) {
  const kept = { ...p, text: clean(p.text) }
  await update($, prompts, list => [...list, { ...kept, seq: (list.at(-1)?.seq ?? 0) + 1 }].slice(-MAX_PROMPTS))
  await update($, current, () => p.id)
}

function inputSummary(e: Loose): string {
  const { tool: _t, tool_use_id: _i, agentId: _a, consent: _c, ...args } = e
  try {
    return JSON.stringify(args, null, 0)
  } catch {
    return String(args)
  }
}

type Classified = { kind: NetKind; targets: Target[]; command?: string; confidence: NetConn['confidence'] }

async function classify($: $, e: Loose): Promise<Classified> {
  const tool = String(e.tool)
  if (tool === 'WebFetch' && typeof e.url === 'string') {
    return { kind: 'web', confidence: 'observed', command: e.url, targets: [{ host: hostOf(e.url), url: e.url, protocol: protocolOf(e.url), reason: 'WebFetch tool' }] }
  }
  if (tool === 'WebSearch') {
    return { kind: 'web', confidence: 'observed', command: String(e.query ?? ''), targets: [{ host: await apiHost($), protocol: 'HTTPS', reason: 'server-side web search run by the API' }] }
  }
  if (SHELL_TOOLS.has(tool)) {
    const ws = (e.ws as Loose | undefined)?.url
    if (typeof ws === 'string') {
      return { kind: 'shell', confidence: 'observed', command: ws, targets: [{ host: hostOf(ws), url: ws, protocol: protocolOf(ws), reason: 'Monitor WebSocket' }] }
    }
    if (typeof e.command !== 'string') return localCall(tool, e)
    const shares = (await shareTargets($, e.command)).map(t => ({ ...t, kind: 'share' as const }))
    const targets = [...detectShell(e.command), ...shares]
    if (targets.length > 0) return { kind: targets.length === shares.length ? 'share' : 'shell', confidence: 'inferred', command: e.command, targets }
    const maybe = detectUncertain(e.command)
    if (maybe !== undefined) return { kind: 'shell', confidence: 'uncertain', command: e.command, targets: [maybe] }
    return localCall(tool, e)
  }
  if (tool.startsWith('mcp__')) {
    const [, server = '?', name = '?'] = tool.split('__')
    if (server.startsWith('claude_ai_')) {
      return { kind: 'service', confidence: 'observed', command: `${server} → ${name}`, targets: [{ host: 'claude.ai (MCP proxy)', protocol: 'HTTPS', reason: `claude.ai connector ${server.slice(10)}` }] }
    }
    return { kind: 'mcp', confidence: 'observed', command: `${server} → ${name}`, targets: [{ host: `mcp:${server}`, protocol: 'MCP', reason: 'MCP server call (stdio servers stay local; http/sse servers go out)' }] }
  }
  if (SERVICE_TOOLS.has(tool)) {
    const url = typeof e.url === 'string' ? e.url : undefined
    return { kind: 'service', confidence: 'observed', command: tool, targets: [{ host: url ? hostOf(url) : 'claude.ai', url, protocol: 'HTTPS', reason: `${tool} talks to claude.ai` }] }
  }
  const paths = PATH_FIELDS.map(k => e[k]).filter((v): v is string => typeof v === 'string')
  const shares = (await Promise.all(paths.map(path => shareTargets($, path)))).flat()
  if (shares.length > 0) {
    return { kind: 'share', confidence: 'observed', command: paths.join(' '), targets: shares.map(t => ({ ...t, reason: `${tool} on a ${t.reason}` })) }
  }
  return localCall(tool, e)
}

/** Any other tool call: recorded as local so each prompt's calls are complete. */
function localCall(tool: string, e: Loose): Classified {
  const what = ['command', 'file_path', 'notebook_path', 'pattern', 'path', 'skill', 'query', 'description', 'prompt']
    .map(k => e[k])
    .find((v): v is string => typeof v === 'string' && v !== '')
  return {
    kind: 'local',
    confidence: 'local',
    command: what ?? trunc(inputSummary(e), 200),
    targets: [{ host: 'local', protocol: '—', reason: `${tool} has no known network access` }],
  }
}

function resultDetails(tool: string, r: Loose | undefined, text: string | undefined): { p: Partial<NetConn>; more: NetDetail[] } {
  const more: NetDetail[] = []
  const p: Partial<NetConn> = {}
  if (r === undefined) return { p, more }
  if (tool === 'WebFetch') {
    if (typeof r.code === 'number') p.statusText = `HTTP ${r.code} ${String(r.codeText ?? '')}`.trim()
    if (typeof r.bytes === 'number') p.bytes = r.bytes
    if (typeof r.durationMs === 'number') more.push({ key: 'Fetch time', value: fmtDur(r.durationMs) })
    if (typeof r.url === 'string') more.push({ key: 'Final URL', value: r.url })
    if (typeof r.result === 'string' && r.result.trim()) more.push({ key: 'Response', value: trunc(r.result.trim(), 2000) })
  } else if (tool === 'WebSearch') {
    const hits: string[] = []
    for (const block of (r.results as unknown[]) ?? []) {
      if (typeof block === 'object' && block !== null) {
        for (const hit of ((block as Loose).content as Loose[]) ?? []) hits.push(`${String(hit.title)} — ${String(hit.url)}`)
      }
    }
    p.statusText = `${hits.length} results`
    if (typeof r.searchCount === 'number') more.push({ key: 'Searches', value: String(r.searchCount) })
    if (typeof r.durationSeconds === 'number') more.push({ key: 'Search time', value: fmtDur(r.durationSeconds * 1000) })
    const hosts = [...new Set(hits.map(h => hostOf(h.split(' — ').at(-1) ?? '')))]
    if (hosts.length) more.push({ key: 'Result hosts', value: hosts.join(', ') })
    hits.slice(0, 10).forEach((h, i) => more.push({ key: `Result ${i + 1}`, value: h }))
    const notes = ((r.results as unknown[]) ?? []).filter((x): x is string => typeof x === 'string' && x.trim() !== '')
    if (notes.length) more.push({ key: 'Response', value: trunc(notes.join('\n').trim(), 2000) })
  } else if (SHELL_TOOLS.has(tool)) {
    if (r.interrupted === true) p.statusText = 'interrupted'
    if (typeof r.backgroundTaskId === 'string') more.push({ key: 'Background task', value: r.backgroundTaskId })
    if (typeof r.timedOutAfterMs === 'number') more.push({ key: 'Timed out after', value: fmtDur(r.timedOutAfterMs) })
    if (r.dangerouslyDisableSandbox === true) more.push({ key: 'Sandbox', value: 'overridden' })
    if (typeof r.stdout === 'string') p.bytes = r.stdout.length + (typeof r.stderr === 'string' ? r.stderr.length : 0)
    if (typeof r.stderr === 'string' && r.stderr.trim()) more.push({ key: 'stderr (head)', value: trunc(r.stderr.trim(), 400) })
    if (typeof r.stdout === 'string' && r.stdout.trim()) more.push({ key: 'stdout (head)', value: trunc(r.stdout.trim(), 400) })
  } else if (text !== undefined) {
    p.bytes = text.length
    more.push({ key: 'Response (head)', value: trunc(oneLine(text), 300) })
  }
  return { p, more }
}

/**
 * Fetches a WebFetch connection's URL again, as the pane's own request, and
 * keeps the raw body under the connection's id. WebFetch hands mods only its
 * processed output, so this second request is the only way to the bytes; it
 * is listed as a connection of its own.
 */
async function fetchRaw($: $, c: NetConn) {
  const url = c.details.find(d => d.key === 'Final URL')?.value ?? c.url
  if (url === undefined) return
  const at = await $.clock.now()
  const put = (r: NetRaw) => update($, raw, m => Object.fromEntries([...Object.entries(m).filter(([k]) => k !== c.id), [c.id, r]].slice(-MAX_RAW)))
  await put({ state: 'loading', url, at })
  const id = mkId(at)
  await addConn($, {
    id,
    kind: 'web',
    source: 'net-connections',
    host: hostOf(url),
    url,
    protocol: protocolOf(url),
    confidence: 'observed',
    reason: `raw response of #${c.seq}, fetched again by this pane`,
    startedAt: at,
    status: 'running',
    promptId: c.promptId,
    command: url,
    details: [],
  })
  try {
    const res = await $.http.fetch(url)
    const end = await $.clock.now()
    await put({ state: 'ok', url, at, status: res.status, headers: res.headers, text: printable(res.text.slice(0, RAW_MAX)), length: res.text.length })
    await patchConn($, id, { endedAt: end, status: res.ok ? 'ok' : 'error', statusText: `HTTP ${res.status}`, bytes: res.text.length }, [
      { key: 'Content type', value: res.headers['content-type'] ?? '—' },
    ])
  } catch (err) {
    const end = await $.clock.now()
    const msg = String((err as Error)?.message ?? err)
    await put({ state: 'error', url, at, error: msg })
    await patchConn($, id, { endedAt: end, status: 'error', statusText: trunc(msg, 120) })
  }
}

// ---------- watching shell processes (Windows) ----------

// The poller (./poller) stops this long after the last shell call ended, once nothing it saw is open.
const WATCH_IDLE_MS = 30_000
const WATCH_MAX_MS = 60 * 60 * 1000
// A shell call's shell starts a moment before the hook runs; the poller counts processes from this far back.
const WATCH_SLACK_MS = 5_000
const MAX_SHELL_CALLS = 200

type ShellCall = {
  tool: string
  toolUseId?: string
  agentId?: string
  promptId?: string
  command?: string
  start: number
  end?: number
  /** The call's own rows, which list what the poller saw it connect to. */
  connIds: string[]
}


const shellCalls: ShellCall[] = []
const namesByAddr = new Map<string, string[]>()
let watching = false
// Set once the poller could not start (no PowerShell, a refused spawn): shell calls stay inferred.
let watchBroken = false
let lastShellActivity = 0
let onWindowsCache: boolean | undefined

async function onWindows($: $): Promise<boolean> {
  onWindowsCache ??= (await $.env.get('OS')) === 'Windows_NT'
  return onWindowsCache
}

/** The shell call running when a process Claude Code started came up: the latest one, a second's slack each side. */
function callAt(started: number): ShellCall | undefined {
  let best: ShellCall | undefined
  for (const c of shellCalls) {
    if (c.start - 1000 <= started && (c.end === undefined || started <= c.end + 1000) && (best === undefined || c.start > best.start)) best = c
  }
  return best
}

/**
 * Runs the poller while shell calls run and a while after, recording each
 * connection it sees as an observed row of the call whose processes made it.
 * One poller for the session: started by the first shell call, it stops once
 * idle and the next shell call starts it again.
 */
async function watchShells($: $) {
  if (watching || watchBroken) return
  watching = true
  const t0 = (await $.clock.now()) - WATCH_SLACK_MS
  const open = new Map<string, string>()
  const byAddr = new Map<string, string[]>()
  const byTop = new Map<number, ShellCall | null>()
  let buf = ''
  let ready = false
  try {
    const stream = $.process.spawn({
      argv: ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', 'iex ([Console]::In.ReadToEnd())'],
      env: { NETCONN_T0: String(t0), NETCONN_MAX_MS: String(WATCH_MAX_MS), NETCONN_EVERY_MS: '25' },
      input: POLL_SCRIPT,
    })
    for await (const chunk of stream) {
      if (chunk.stream !== 'stdout') continue
      buf += chunk.text
      for (let nl = buf.indexOf('\n'); nl >= 0; nl = buf.indexOf('\n')) {
        const ev = parsePollLine(buf.slice(0, nl).trim())
        buf = buf.slice(nl + 1)
        if (ev === undefined) continue
        const at = await $.clock.now()
        if (ev.ev === 'ready') ready = true
        else if (ev.ev === 'open') {
          if (!byTop.has(ev.top)) byTop.set(ev.top, callAt(ev.topStart) ?? null)
          const call = byTop.get(ev.top) ?? undefined
          const names = namesByAddr.get(ev.addr)
          const proc = `${ev.name ?? 'process'} (PID ${ev.pid})`
          const id = mkId(at)
          await addConn($, {
            id,
            kind: 'shell',
            source: call?.tool ?? 'Claude Code',
            host: names?.[0] ?? ev.addr,
            protocol: portProtocol(ev.port),
            confidence: 'observed',
            reason: `${proc} connected; seen in the TCP table`,
            seenByPoller: true,
            startedAt: at,
            status: 'running',
            promptId: call?.promptId ?? (await originFor($, undefined)),
            agentId: call?.agentId,
            toolUseId: call?.toolUseId,
            command: ev.cmd ? shortCommand(ev.cmd) : ev.name,
            details: [
              { key: 'Process', value: proc },
              ...(ev.cmd ? [{ key: 'Command line', value: ev.cmd }] : []),
              { key: 'Remote', value: `${ev.addr} port ${ev.port}` },
              { key: 'Local', value: ev.local },
              ...(names ? [{ key: 'DNS names', value: names.join(', ') }] : []),
              {
                key: 'Started by',
                value: call
                  ? `${call.tool} call${call.command ? `: ${trunc(oneLine(call.command), 300)}` : ''}`
                  : 'a process Claude Code started outside any shell call (a hook, an MCP server, git, …)',
              },
            ],
          })
          open.set(ev.key, id)
          byAddr.set(ev.addr, [...(byAddr.get(ev.addr) ?? []), id])
        } else if (ev.ev === 'close') {
          const id = open.get(ev.key)
          open.delete(ev.key)
          if (id !== undefined) await patchConn($, id, { endedAt: at, status: 'ok', statusText: 'closed' })
        } else if (ev.ev === 'names') {
          namesByAddr.set(ev.addr, ev.names)
          for (const id of byAddr.get(ev.addr) ?? []) {
            await patchConn($, id, { host: ev.names[0] }, [{ key: 'DNS names', value: ev.names.join(', ') }])
          }
          byAddr.delete(ev.addr)
        }
      }
      const idle = !shellCalls.some(c => c.end === undefined) && open.size === 0
      if (idle && (await $.clock.now()) - lastShellActivity > WATCH_IDLE_MS) break
    }
  } catch {
    watchBroken = true
  } finally {
    // A poller that never got ready will not get ready the next time either.
    if (!ready) watchBroken = true
    watching = false
    const end = await $.clock.now()
    for (const id of open.values()) await patchConn($, id, { endedAt: end, status: 'ok', statusText: 'last seen' })
    if (!watchBroken && shellCalls.some(c => c.end === undefined)) void watchShells($)
  }
}

// ---------- drawing ----------

function setView($: $, fn: (v: NetView) => NetView) {
  return update($, view, fn)
}

const MAX_BACK = 30

/** Moves to another view and remembers the one it leaves, for `b`. */
function navigate($: $, fn: (v: NetView) => NetView) {
  return update($, view, v => {
    const { back = [], ...here } = v
    return { ...fn(v), back: [...back, here].slice(-MAX_BACK) }
  })
}

/** Returns to the view `navigate` left; with none left, to the list. */
function goBack($: $) {
  return update($, view, (v): NetView => {
    const back = v.back ?? []
    const prev = back.at(-1)
    return prev !== undefined ? { ...prev, back: back.slice(0, -1) } : { ...v, mode: 'list', back: [] }
  })
}

/**
 * The file-share targets a path or command names: UNC paths (Windows only;
 * `\\` and `//` mean nothing of the kind on macOS and Linux) and paths on a
 * network drive or mount.
 */
async function shareTargets($: $, text: string): Promise<Target[]> {
  const m = await read($, mounts)
  return [...(m.platform === 'posix' ? [] : detectShare(text)), ...detectMounts(text, m.list)]
}

async function run($: $, argv: readonly string[]): Promise<string | undefined> {
  try {
    const r = await $.process.run(argv, { timeoutMs: 15_000 })
    return r.exitCode === 0 ? r.stdout : undefined
  } catch {
    return undefined // not installed on this system
  }
}

/**
 * Reads the network drives (Windows: CIM, else `net use`) or mounts (macOS,
 * Linux: `mount`) into state. A failed lookup keeps the last list and says why.
 */
async function loadMounts($: $): Promise<NetMounts> {
  const isWindows = (await $.env.get('OS')) === 'Windows_NT'
  const now = await $.clock.now()
  let list: NetMount[] | undefined
  let error: string | undefined
  if (isWindows) {
    const cim = await run($, ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', CIM_DRIVES])
    if (cim !== undefined) list = driveMounts(parseCimDrives(cim))
    else {
      const net = await run($, ['net', 'use'])
      if (net !== undefined) list = driveMounts(parseNetUse(net))
      else error = 'neither Get-CimInstance nor net use answered'
    }
  } else {
    const out = await run($, ['mount'])
    if (out !== undefined) list = parseMountOutput(out)
    else error = 'mount did not answer'
  }
  const platform = isWindows ? 'windows' : 'posix'
  return update($, mounts, prev => ({
    platform,
    list: list ?? prev.list,
    at: list ? now : prev.at,
    isLoaded: list !== undefined || prev.isLoaded === true,
    ...(error ? { error } : {}),
  }))
}

function mountLine(m: NetMount): string {
  return `${m.root} → ${m.source} (${m.protocol})`
}

export const register: Register = on => {
  let lastCommand: { id: string; at: number; used: boolean } | undefined

  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: 'net',
      description: 'Show the network connections this session made, by prompt and command',
      // Runs at once while a turn is in flight: opening the pane never needs to wait for the turn or interrupt it.
      immediate: true,
    })
    if (e.isInteractive) void $.ui.open({ id: PANE, title: TITLE })
    void loadMounts($)
    $.clock.every(MOUNT_REFRESH_MS, () => void loadMounts($))
    return next(e)
  })

  on('command.run', { command: 'net' }, async ($, e) => {
    const arg = e.args.trim()
    if (arg === 'clear') {
      await update($, conns, () => [])
      await update($, prompts, () => [])
      await update($, current, () => null)
      await update($, agents, () => ({}))
      await setView($, () => ({ mode: 'list', filter: 'all', page: 0 }))
      return { text: 'Network log cleared.' }
    }
    if (arg === 'drives' || arg === 'mounts') {
      const m = await loadMounts($)
      const what = m.platform === 'windows' ? 'mapped network drives' : 'network mounts'
      if (m.error !== undefined && m.isLoaded !== true) return { text: `Could not list ${what}: ${m.error}.` }
      const head = m.list.length === 0 ? `No ${what}.` : `${what[0]!.toUpperCase()}${what.slice(1)}:\n${m.list.map(x => `  ${mountLine(x)}`).join('\n')}`
      return { text: m.error !== undefined ? `${head}\n(last lookup failed: ${m.error}; showing the previous list)` : head }
    }
    const opened = await $.ui.open({ id: PANE, title: TITLE, focus: true })
    const n = (await read($, conns)).length
    const so = `${n} connection${n === 1 ? '' : 's'} so far`
    if (!opened.isPlaced) return { text: `Network pane is open but not shown here (${so}): ${opened.reason}` }
    return { text: `Network pane opened (${so}).` }
  })

  // Slash commands are origins too: a command that runs a turn keeps its name.
  on('command.run', async ($, e, next) => {
    if (e.command === 'net') return next(e)
    const now = await $.clock.now()
    const id = `cmd-${mkId(now)}`
    await addPrompt($, { id, kind: 'command', text: `/${e.command}${e.args ? ` ${e.args}` : ''}`, at: now })
    lastCommand = { id, at: now, used: false }
    return next(e)
  })

  on('turn.start', async ($, e, next) => {
    const now = await $.clock.now()
    if (lastCommand !== undefined && !lastCommand.used && now - lastCommand.at < 5000) {
      lastCommand.used = true
      await update($, current, () => lastCommand!.id)
    } else {
      await addPrompt($, {
        id: e.turnId,
        kind: e.text ? 'prompt' : 'other',
        text: e.text || '(continuation / background notification)',
        at: now,
      })
    }
    return next(e)
  })

  // Every model request is an HTTPS stream to the API.
  on('turn.step', async function* ($, e, next) {
    const t0 = await $.clock.now()
    const id = mkId(t0)
    const host = await apiHost($)
    await addConn($, {
      id,
      kind: 'model',
      source: e.agentId ? 'subagent model request' : 'model request',
      host,
      url: `https://${host}/v1/messages`,
      protocol: 'HTTPS (SSE stream)',
      confidence: 'observed',
      reason: 'turn step: one Messages API request',
      startedAt: t0,
      status: 'running',
      promptId: await originFor($, e.agentId),
      agentId: e.agentId,
      command: `${e.model} · step ${e.index} · ${e.messageCount} messages`,
      details: [
        { key: 'Model', value: e.model },
        ...(e.effort !== undefined ? [{ key: 'Effort', value: String(e.effort) }] : []),
        { key: 'Turn', value: e.turnId },
        { key: 'Step', value: String(e.index) },
        { key: 'Messages sent', value: String(e.messageCount) },
      ],
    })
    let firstAt: number | undefined
    let chunks = 0
    let outChars = 0
    try {
      const stream = next(e)
      for await (const chunk of stream) {
        if (firstAt === undefined && chunk.kind !== 'engine') firstAt = await $.clock.now()
        chunks += 1
        if (chunk.kind === 'text') outChars += chunk.text.length
        if (chunk.kind === 'input') outChars += chunk.json.length
        yield chunk
      }
      const r = await stream.result
      const end = await $.clock.now()
      const u = r.usage
      const more: NetDetail[] = [
        { key: 'Time to first chunk', value: firstAt === undefined ? '—' : fmtDur(firstAt - t0) },
        { key: 'Stream chunks', value: String(chunks) },
        { key: 'Stop reason', value: String(r.stopReason ?? 'none (failed or interrupted)') },
      ]
      if (u) {
        more.push(
          { key: 'Answered by', value: u.model },
          { key: 'Input tokens', value: String(u.input_tokens) },
          { key: 'Cache read tokens', value: String(u.cache_read_input_tokens) },
          { key: 'Cache write tokens', value: String(u.cache_creation_input_tokens) },
          { key: 'Output tokens', value: String(u.output_tokens) },
        )
      }
      if (r.toolUses.length) more.push({ key: 'Tools requested', value: r.toolUses.map(t => String((t as Loose).name ?? (t as Loose).tool ?? '?')).join(', ') })
      if (r.answer) more.push({ key: 'Answer (head)', value: trunc(oneLine(r.answer), 300) })
      await patchConn(
        $,
        id,
        {
          endedAt: end,
          status: r.stopReason === null ? 'error' : 'ok',
          statusText: u ? `${fmtNum(u.input_tokens + u.cache_read_input_tokens + u.cache_creation_input_tokens)} in / ${fmtNum(u.output_tokens)} out` : String(r.stopReason ?? 'no response'),
          bytes: outChars || undefined,
        },
        more,
      )
      return r
    } catch (err) {
      await patchConn($, id, { endedAt: await $.clock.now(), status: 'error', statusText: String((err as Error)?.message ?? err).slice(0, 120) })
      throw err
    }
  })

  // Tools that reach the network: web, shell commands that look networked, MCP, claude.ai services.
  on('tool.call', async ($, e, next) => {
    const loose = e as unknown as Loose
    const found = await classify($, loose)
    const t0 = await $.clock.now()
    const promptId = await originFor($, e.agentId)
    const ids: string[] = []
    for (const t of found.targets) {
      const id = mkId(t0)
      ids.push(id)
      await addConn($, {
        id,
        kind: t.kind ?? found.kind,
        source: String(e.tool),
        host: t.host,
        url: t.url,
        protocol: t.protocol,
        confidence: found.confidence,
        reason: t.reason,
        startedAt: t0,
        status: 'running',
        promptId,
        agentId: e.agentId,
        toolUseId: e.tool_use_id,
        command: found.command,
        details: [{ key: 'Tool input', value: trunc(inputSummary(loose), 600) }],
      })
    }
    let shell: ShellCall | undefined
    if (SHELL_TOOLS.has(String(e.tool)) && (await onWindows($))) {
      shell = { tool: String(e.tool), toolUseId: e.tool_use_id, agentId: e.agentId, promptId, command: typeof loose.command === 'string' ? loose.command : undefined, start: t0, connIds: ids }
      shellCalls.push(shell)
      shellCalls.splice(0, Math.max(0, shellCalls.length - MAX_SHELL_CALLS))
      lastShellActivity = t0
      void watchShells($)
    }
    let ran
    try {
      ran = await next(e)
    } catch (err) {
      const end = await $.clock.now()
      if (shell) {
        shell.end = end
        lastShellActivity = end
      }
      for (const id of ids) await patchConn($, id, { endedAt: end, status: 'error', statusText: String((err as Error)?.message ?? err).slice(0, 120) })
      throw err
    }
    const end = await $.clock.now()
    if (shell) {
      shell.end = end
      lastShellActivity = end
    }
    const status: NetStatus = ran.deny !== undefined ? 'denied' : ran.isError ? 'error' : 'ok'
    const { p, more } = resultDetails(String(e.tool), ran.result as Loose | undefined, ran.text)
    if (ran.deny !== undefined) more.push({ key: 'Denied', value: ran.deny })
    if (ran.isError && ran.text) more.push({ key: 'Error', value: trunc(oneLine(ran.text), 400) })
    for (const id of ids) {
      await patchConn($, id, { endedAt: end, status, statusText: p.statusText ?? (status === 'ok' ? 'done' : status), ...(p.bytes !== undefined ? { bytes: p.bytes } : {}) }, more)
    }
    return ran
  })

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const { Box } = $.ui.resolve(e)
    const body = await renderPane($, e)
    return (
      <Box flexDirection="column" flexGrow={1} backgroundColor="black" minHeight={e.viewport?.rows}>
        {body}
      </Box>
    )
  })
}

/** The pane's content; `ui.render` paints it on a black ground. */
async function renderPane($: $, e: RenderInput<'Pane'>) {
  const { Box, Text, Button } = $.ui.resolve(e)
  const all = await read($, conns)
  const ps = await read($, prompts)
  const v = await read($, view)
  const width = Math.max(30, e.props.bodyColumns)
  const rows = Math.max(8, (e.viewport?.rows ?? 30) - 2)
  const promptById = new Map(ps.map(p => [p.id, p]))
  // A row the poller saw belongs to the tool call with its tool use id: that call's own row.
  const isSeen = (c: NetConn) => c.seenByPoller === true
  const callRows = new Map<string, NetConn>()
  for (const c of all) if (c.toolUseId !== undefined && !isSeen(c) && !callRows.has(c.toolUseId)) callRows.set(c.toolUseId, c)
  const parentOf = (c: NetConn) => (isSeen(c) && c.toolUseId !== undefined ? callRows.get(c.toolUseId) : undefined)
  const seenOf = new Map<string, NetConn[]>()
  for (const c of all) {
    const p = parentOf(c)
    if (p !== undefined) seenOf.set(p.id, [...(seenOf.get(p.id) ?? []), c])
  }
  const promptLabel = (id?: string) => {
    const p = id === undefined ? undefined : promptById.get(id)
    return p === undefined ? '(no prompt)' : `${p.kind === 'command' ? 'C' : 'P'}${p.seq}`
  }

  const showLocal = v.showLocal === true
  const net = all.filter(c => c.kind !== 'local')
  const networked = (c: NetConn) => c.kind === 'local' && seenOf.has(c.id)
  const nNetworked = all.filter(networked).length
  const counts: Record<string, number> = { all: showLocal ? all.length : net.length + nNetworked, model: 0, web: 0, shell: nNetworked, mcp: 0, service: 0, share: 0, local: 0 }
  for (const c of all) counts[c.kind] = (counts[c.kind] ?? 0) + 1
  const uncertain = net.filter(c => c.confidence === 'uncertain').length
  const hosts = new Set(net.map(c => c.host).filter(h => !PLACEHOLDER_HOSTS.has(h)))
  const tokIn = all.reduce((n, c) => n + Number(c.details.find(d => d.key === 'Input tokens')?.value ?? 0) + Number(c.details.find(d => d.key === 'Cache read tokens')?.value ?? 0), 0)
  const tokOut = all.reduce((n, c) => n + Number(c.details.find(d => d.key === 'Output tokens')?.value ?? 0), 0)
  const running = net.filter(c => c.status === 'running').length

  const header = (
    <Box flexDirection="column">
      <Text wrap="truncate-end">
        <Text bold color="cyan">NETWORK CONNECTIONS</Text>
        <Text bold>{` · ${net.length} connections`}</Text>
        {uncertain > 0 ? <Text color="yellow">{` (${uncertain} uncertain)`}</Text> : null}
        {counts.share ? <Text color={KIND_COLOR.share} bold>{` · ⇄ ${counts.share} file-share access${counts.share === 1 ? '' : 'es'}`}</Text> : null}
        <Text dimColor>{` · ${hosts.size} hosts · ${counts.local} local tool calls · ${ps.length} prompts · ${fmtNum(tokIn)}↑ ${fmtNum(tokOut)}↓ tokens`}</Text>
        {running > 0 ? <Text color="yellow">{` · ${running} open`}</Text> : null}
      </Text>
      <Box flexDirection="row" flexWrap="wrap" columnGap={1}>
        <Button key="v-list" plain hotkey="l" dimColor={v.mode !== 'list'} label="list" onPress={() => setView($, x => ({ ...x, mode: 'list', page: 0, back: [] }))} />
        <Button key="v-prompts" plain hotkey="g" dimColor={v.mode !== 'prompts'} label="by prompt" onPress={() => setView($, x => ({ ...x, mode: 'prompts', page: 0, back: [] }))} />
        <Button key="v-hosts" plain hotkey="h" dimColor={v.mode !== 'hosts'} label="by host" onPress={() => setView($, x => ({ ...x, mode: 'hosts', page: 0, back: [] }))} />
        <Text dimColor>│</Text>
        <Button key="toggle-local" plain hotkey="z" dimColor={!showLocal} label={`local tool calls: ${showLocal ? 'shown' : 'hidden'}`} onPress={() => setView($, x => ({ ...x, showLocal: x.showLocal !== true, page: 0 }))} />
      </Box>
    </Box>
  )

  // ---- detail ----
  if (v.mode === 'detail') {
    const list = scoped(all, v, networked)
    const idx = list.findIndex(c => c.id === v.selected)
    const c = idx >= 0 ? list[idx] : all.find(x => x.id === v.selected)
    if (c === undefined) {
      return (
        <Box flexDirection="column">
          {header}
          <Text dimColor>That connection is gone.</Text>
          <Button key="back" hotkey="b" label="back" onPress={() => goBack($)} />
        </Box>
      )
    }
    const p = c.promptId ? promptById.get(c.promptId) : undefined
    const parent = parentOf(c)
    const seen = seenOf.get(c.id) ?? []
    const linked = new Set([parent?.id, ...seen.map(x => x.id)])
    const siblings = all.filter(x => x.promptId === c.promptId && x.id !== c.id && !linked.has(x.id))
    const rowLabel = (x: NetConn) => trunc(`#${x.seq} ${KIND_LABEL[x.kind]} ${x.host}  ${oneLine(x.command ?? x.statusText ?? '')}`, width - 4)
    const mark = STATUS_MARK[c.status]
    const keyW = 20
    const field = (k: string, value: string, color?: string) => (
      <Box flexDirection="row">
        <Box width={keyW} flexShrink={0}><Text dimColor>{k}</Text></Box>
        <Box flexGrow={1}><Text wrap="wrap" color={color}>{trunc(printable(value), 9_000)}</Text></Box>
      </Box>
    )
    const go = (to?: NetConn) => to && setView($, x => ({ ...x, selected: to.id }))
    const copyText = c.url ?? c.command ?? c.host

    // WebFetch: its processed output, or the page's raw body fetched again on request.
    const isFetch = c.source === 'WebFetch' && c.url !== undefined
    const showRaw = v.response === 'raw'
    const r = isFetch ? (await read($, raw))[c.id] : undefined
    const toolOut = c.details.find(d => d.key === 'Response')?.value
    const body = r?.text === undefined ? '' : printable(r.text)
    const rawPages = Math.max(1, Math.ceil(body.length / RAW_PAGE))
    const rawPage = Math.min(Math.max(0, v.rawPage ?? 0), rawPages - 1)
    const pageText = body.slice(rawPage * RAW_PAGE, (rawPage + 1) * RAW_PAGE)
    const pickRaw = () => {
      void setView($, x => ({ ...x, response: 'raw', rawPage: 0 }))
      if (r === undefined || r.state === 'error') void fetchRaw($, c)
    }
    const responseSection = (
      <Box flexDirection="column" marginTop={1}>
        <Box flexDirection="row" columnGap={1}>
          <Text bold>Response</Text>
          <Button key="resp-tool" plain hotkey="w" dimColor={showRaw} label="tool output" onPress={() => setView($, x => ({ ...x, response: 'tool' }))} />
          <Button key="resp-raw" plain hotkey="r" dimColor={!showRaw} label="raw page" onPress={pickRaw} />
          {showRaw && r !== undefined && r.state !== 'loading' ? (
            <Button key="resp-refetch" plain hotkey="f" label="fetch again" onPress={() => void fetchRaw($, c)} />
          ) : null}
        </Box>
        {!showRaw ? (
          <Text wrap="wrap" dimColor={toolOut === undefined}>{toolOut ?? (c.status === 'running' ? 'Still running.' : 'WebFetch returned no output.')}</Text>
        ) : r === undefined ? (
          <Text dimColor>Press r to fetch the page.</Text>
        ) : r.state === 'loading' ? (
          <Text color="yellow">{`Fetching ${r.url} …`}</Text>
        ) : r.state === 'error' ? (
          <Text color="red" wrap="wrap">{`Fetch failed: ${r.error ?? 'unknown error'}`}</Text>
        ) : (
          <Box flexDirection="column">
            <Text wrap="wrap" color="yellow">{`Fetched again by this pane at ${fmtTime(r.at)}, not the bytes WebFetch received: mods only see the tool's output. The page may have changed, or answer this request differently.`}</Text>
            {field('Status', `HTTP ${r.status ?? '?'}`, r.status !== undefined && r.status < 400 ? undefined : 'red')}
            {field('Content type', r.headers?.['content-type'] ?? '—')}
            {field('Length', `${r.length ?? 0} chars${(r.length ?? 0) > RAW_MAX ? ` — first ${RAW_MAX} shown` : ''}`)}
            {rawPages > 1 ? (
              <Box flexDirection="row" columnGap={1} marginTop={1}>
                <Button key="raw-prev" plain hotkey="k" dimColor={rawPage === 0} label="previous part" onPress={() => setView($, x => ({ ...x, rawPage: Math.max(0, rawPage - 1) }))} />
                <Text dimColor>{`part ${rawPage + 1}/${rawPages}`}</Text>
                <Button key="raw-next" plain hotkey="j" dimColor={rawPage >= rawPages - 1} label="next part" onPress={() => setView($, x => ({ ...x, rawPage: Math.min(rawPages - 1, rawPage + 1) }))} />
              </Box>
            ) : null}
            <Text> </Text>
            {body === '' ? <Text dimColor>(empty body)</Text> : chunks(pageText, RAW_CHUNK).map((t, i) => <Text key={`raw-${rawPage}-${i}`} wrap="wrap">{t}</Text>)}
          </Box>
        )}
      </Box>
    )
    return (
      <Box flexDirection="column">
        {header}
        <Box flexDirection="row" columnGap={1} marginTop={1}>
          <Button key="back" plain hotkey="b" label="back" onPress={() => goBack($)} />
          <Button key="prev" plain hotkey="p" dimColor={idx <= 0} label="newer" onPress={() => go(list[idx - 1])} />
          <Button key="next" plain hotkey="n" dimColor={idx < 0 || idx >= list.length - 1} label="older" onPress={() => go(list[idx + 1])} />
          <Button key="same-prompt" plain hotkey="o" label="all from this prompt" onPress={() => navigate($, x => ({ ...x, mode: 'list', promptId: c.promptId ?? '', host: undefined, filter: 'all', page: 0 }))} />
          <Button key="same-host" plain hotkey="t" label="all to this host" onPress={() => navigate($, x => ({ ...x, mode: 'list', host: c.host, promptId: undefined, filter: 'all', page: 0 }))} />
          <Button key="copy" plain hotkey="c" label="copy" onPress={press => void $.ui.copy({ text: copyText, surface: press.surface })} />
        </Box>
        <Text> </Text>
        <Text wrap="truncate-end">
          <Text color={mark.color}>{mark.glyph} </Text>
          <Text color={KIND_COLOR[c.kind]} bold>{KIND_LABEL[c.kind]} </Text>
          <Text bold>{c.host}</Text>
          <Text dimColor>{`  #${c.seq}`}</Text>
        </Text>
        {c.kind === 'share' ? (
          <Box flexDirection="column" borderStyle="round" borderColor={KIND_COLOR.share} paddingX={1} marginY={1}>
            <Text color={KIND_COLOR.share} bold>⇄ File-share access — not a web or API connection</Text>
            <Text wrap="wrap">{`The path lies on the network file system ${c.url ?? c.host}. The operating system reaches it over ${c.protocol}, opening or reusing a session to ${c.host} for the file access itself; nothing goes to a web server or API.`}</Text>
            <Text wrap="wrap" dimColor>{'Duration and size are those of the tool call; the file-system session may outlive it, be shared with other programs, and serve reads from a local cache.'}</Text>
          </Box>
        ) : null}
        {field('Status', `${c.status}${c.statusText ? ` — ${c.statusText}` : ''}`, mark.color)}
        {c.url ? field('URL', c.url) : null}
        {field('Protocol', c.protocol)}
        {field('Evidence', `${EVIDENCE_TEXT[c.confidence]} — ${c.reason}`, c.confidence === 'inferred' || c.confidence === 'uncertain' ? 'yellow' : c.confidence === 'local' ? 'gray' : undefined)}
        {field('Started', `${fmtTime(c.startedAt)}`)}
        {field('Duration', c.endedAt === undefined ? 'still open' : fmtDur(durOf(c)))}
        {c.bytes !== undefined ? field(c.kind === 'model' ? 'Streamed out' : 'Size', c.kind === 'model' ? `${c.bytes} chars` : fmtBytes(c.bytes)) : null}
        {field('Made by', c.source + (c.toolUseId ? ` (${c.toolUseId})` : ''))}
        {c.agentId ? field('Subagent', c.agentId) : null}
        {parent !== undefined ? (
          <Box flexDirection="column" marginTop={1}>
            <Text bold>Caused by</Text>
            <Text wrap="wrap" dimColor>{`The ${parent.source} call whose processes opened this connection; the engine reports the call, the poller saw the connection.`}</Text>
            <Button key="parent" plain hotkey="u" label={`↑ ${rowLabel(parent)}`} onPress={() => navigate($, x => ({ ...x, selected: parent.id }))} />
          </Box>
        ) : null}
        {seen.length > 0 ? (
          <Box flexDirection="column" marginTop={1}>
            <Text bold>{`Observed connections of this call (${seen.length})`}</Text>
            <Text wrap="wrap" dimColor>{"What this call's processes connected to, as the poller saw it in the TCP table."}</Text>
            {seen.slice(0, 20).map((x, i) => (
              <Button key={`seen-${x.id}`} plain hotkey={i < 9 ? String(i + 1) : undefined} label={`↳ ${rowLabel(x)}`} onPress={() => navigate($, v2 => ({ ...v2, selected: x.id }))} />
            ))}
          </Box>
        ) : null}
        <Text> </Text>
        <Text bold>Origin</Text>
        {field(promptLabel(c.promptId), p ? `${fmtTime(p.at)}  ${trunc(oneLine(p.text), 600)}` : 'before any prompt (session start)')}
        {c.command ? field(c.kind === 'model' ? 'Request' : 'Command', trunc(c.command, 800)) : null}
        <Text> </Text>
        <Text bold>Details</Text>
        {c.details.filter(d => !(isFetch && d.key === 'Response')).map(d => field(d.key, d.value))}
        {isFetch ? responseSection : null}
        {siblings.length > 0 ? (
          <Box flexDirection="column" marginTop={1}>
            <Text bold>{`Other connections from ${promptLabel(c.promptId)} (${siblings.length})`}</Text>
            {siblings.slice(-8).reverse().map(s => (
              <Button key={`sib-${s.id}`} plain dimColor label={trunc(`#${s.seq} ${KIND_LABEL[s.kind]} ${s.host} ${s.statusText ?? ''}`, width - 2)} onPress={() => navigate($, x => ({ ...x, selected: s.id }))} />
            ))}
          </Box>
        ) : null}
      </Box>
    )
  }

  // ---- by prompt ----
  if (v.mode === 'prompts') {
    const byPrompt = new Map<string, NetConn[]>()
    for (const c of all) {
      const k = c.promptId ?? ''
      byPrompt.set(k, [...(byPrompt.get(k) ?? []), c])
    }
    const items = [...ps].reverse().map(p => ({ p, cs: byPrompt.get(p.id) ?? [] }))
    if (byPrompt.has('')) items.push({ p: { id: '', seq: 0, kind: 'other', text: '(before any prompt)', at: 0 }, cs: byPrompt.get('') ?? [] })
    const room = rows - 6
    const pages = Math.max(1, Math.ceil(items.length / room))
    const page = Math.min(v.page, pages - 1)
    return (
      <Box flexDirection="column">
        {header}
        <Text dimColor>{'Press a prompt to list its connections.'}</Text>
        {items.length === 0 ? <Text dimColor>No prompts yet.</Text> : null}
        {items.slice(page * room, page * room + room).map(({ p, cs }) => {
          const kinds = (['model', 'web', 'shell', 'mcp', 'service', 'share', 'local'] as const).map(k => [k, cs.filter(c => c.kind === k).length] as const).filter(([, n]) => n > 0)
          const tag = p.id === '' ? '—' : `${p.kind === 'command' ? 'C' : 'P'}${p.seq}`
          const netCount = cs.filter(c => c.kind !== 'local').length
          const summary = kinds.map(([k, n]) => `${n} ${KIND_LABEL[k].toLowerCase()}`).join(', ') || 'no tool calls'
          const label = `${tag.padEnd(4)} ${p.at ? fmtTime(p.at) : '        '}  ${String(netCount).padStart(3)} net  ${summary.padEnd(34)} ${oneLine(p.text)}`
          return (
            <Button key={`p-${p.id || 'none'}`} plain dimColor={netCount === 0} label={trunc(label, width - 1)} onPress={() => navigate($, x => ({ ...x, mode: 'list', promptId: p.id, host: undefined, filter: 'all', page: 0 }))} />
          )
        })}
        {pager(page, pages)}
      </Box>
    )
  }

  // ---- by host ----
  if (v.mode === 'hosts') {
    const agg = new Map<string, { n: number; err: number; bytes: number; last: number; kinds: Set<NetKind>; prompts: Set<string> }>()
    for (const c of net) {
      const a = agg.get(c.host) ?? { n: 0, err: 0, bytes: 0, last: 0, kinds: new Set(), prompts: new Set() }
      a.n += 1
      if (c.status === 'error') a.err += 1
      a.bytes += c.kind === 'model' ? 0 : c.bytes ?? 0
      a.last = Math.max(a.last, c.startedAt)
      a.kinds.add(c.kind)
      if (c.promptId) a.prompts.add(c.promptId)
      agg.set(c.host, a)
    }
    // Real hosts first; then the rows whose command named no destination.
    const byCount = (x: [string, { n: number }], y: [string, { n: number }]) => y[1].n - x[1].n
    const entries = [...agg.entries()]
    const items = [...entries.filter(([h]) => !PLACEHOLDER_HOSTS.has(h)).sort(byCount), ...entries.filter(([h]) => PLACEHOLDER_HOSTS.has(h)).sort(byCount)]
    const mnt = await read($, mounts)
    const mountWord = mnt.platform === 'windows' ? 'mapped drives' : 'network mounts'
    const room = rows - 7
    const pages = Math.max(1, Math.ceil(items.length / room))
    const page = Math.min(v.page, pages - 1)
    return (
      <Box flexDirection="column">
        {header}
        <Box flexDirection="row" columnGap={1}>
          <Text color={KIND_COLOR.share} wrap="truncate-end">
            {mnt.isLoaded !== true
              ? mnt.error !== undefined
                ? `Could not list ${mountWord}: ${mnt.error}.`
                : `Looking up ${mountWord}…`
              : mnt.list.length === 0
                ? `No ${mountWord}.`
                : trunc(`⇄ ${mountWord[0]!.toUpperCase()}${mountWord.slice(1)}: ${mnt.list.map(mountLine).join(' · ')}`, width - 22)}
          </Text>
          <Button key="refresh-mounts" plain hotkey="r" label={`refresh ${mnt.platform === 'windows' ? 'drives' : 'mounts'}`} onPress={() => void loadMounts($)} />
        </Box>
        <Text dimColor>{`${'count'.padStart(5)}  ${'last'.padEnd(8)}  ${'prompts'.padStart(7)}  ${'kinds'.padEnd(14)} host`}</Text>
        {items.length === 0 ? <Text dimColor>No connections yet.</Text> : null}
        {items.slice(page * room, page * room + room).map(([host, a], i, shown) => {
          const kinds = [...a.kinds].map(k => KIND_LABEL[k].toLowerCase()).join(',')
          const label = `${String(a.n).padStart(5)}  ${fmtTime(a.last)}  ${String(a.prompts.size).padStart(7)}  ${kinds.padEnd(14)} ${host}${a.err ? `  (${a.err} failed)` : ''}`
          const placeholder = PLACEHOLDER_HOSTS.has(host)
          const firstPlaceholder = placeholder && (i === 0 || !PLACEHOLDER_HOSTS.has(shown[i - 1]![0]))
          return (
            <Box key={`hr-${host}`} flexDirection="column">
              {firstPlaceholder ? <Text dimColor>{'No host named (the command text does not say where it connects):'}</Text> : null}
              <Button key={`h-${host}`} plain dimColor={placeholder} label={trunc(label, width - 1)} onPress={() => navigate($, x => ({ ...x, mode: 'list', host, promptId: undefined, filter: 'all', page: 0 }))} />
            </Box>
          )
        })}
        {pager(page, pages)}
      </Box>
    )
  }

  // ---- list ----
  const list = scoped(all, v, networked)
  const room = rows - 9
  const pages = Math.max(1, Math.ceil(list.length / room))
  const page = Math.min(v.page, pages - 1)
  const scopeText =
    v.promptId !== undefined
      ? `${promptLabel(v.promptId || undefined)}: ${oneLine(promptById.get(v.promptId)?.text ?? '(before any prompt)')}`
      : v.host !== undefined
        ? `host ${v.host}`
        : undefined
  const filters: readonly ['all' | NetKind, string, string][] = [
    ['all', 'a', 'all'],
    ['model', 'm', 'model'],
    ['web', 'w', 'web'],
    ['shell', 's', 'shell'],
    ['mcp', 'x', 'mcp'],
    ['service', 'v', 'service'],
    ['share', 'f', 'share'],
    ['local', 'k', 'local'],
  ]
  const hostW = Math.max(12, Math.min(34, Math.floor(width * 0.3)))
  return (
    <Box flexDirection="column">
      {header}
      <Box flexDirection="row" flexWrap="wrap" columnGap={1}>
        {filters.map(([f, key, label]) => (
          <Button key={`f-${f}`} plain hotkey={key} dimColor={v.filter !== f} label={`${label} ${counts[f]}`} onPress={() => setView($, x => ({ ...x, filter: f, page: 0 }))} />
        ))}
        {(v.back?.length ?? 0) > 0 ? <Button key="list-back" plain hotkey="b" label="back" onPress={() => goBack($)} /> : null}
      </Box>
      {scopeText !== undefined ? (
        <Box flexDirection="row" columnGap={1}>
          <Text color="cyan" wrap="truncate-end">{trunc(`▸ ${scopeText}`, width - 12)}</Text>
          <Button key="unscope" plain hotkey="u" label="clear" onPress={() => setView($, x => ({ ...x, promptId: undefined, host: undefined, page: 0 }))} />
        </Box>
      ) : null}
      <Text dimColor wrap="truncate-end">{`  ${'#'.padStart(4)} ${'time'.padEnd(8)} ${'kind'.padEnd(5)} ${'host'.padEnd(hostW)} ${'dur'.padStart(6)} ${'from'.padEnd(5)} status / command`}</Text>
      {list.length === 0 ? <Text dimColor>{counts.all === 0 ? 'No network connections yet. Web fetches, model requests, MCP calls and networked shell commands appear here.' : 'Nothing matches this filter.'}</Text> : null}
      {list.slice(page * room, page * room + room).map(c => {
        const mark = STATUS_MARK[c.status]
        const parent = parentOf(c)
        const nSeen = seenOf.get(c.id)?.length ?? 0
        const host = parent !== undefined ? `↳#${parent.seq} ${c.host}` : c.host
        const status = `${c.statusText ?? ''}${nSeen > 0 ? ` → ${nSeen} seen` : ''}`
        const rest = `${String(c.seq).padStart(4)} ${fmtTime(c.startedAt)} ${KIND_LABEL[c.kind].padEnd(5)} ${trunc(host, hostW).padEnd(hostW)} ${fmtDur(durOf(c)).padStart(6)} ${promptLabel(c.promptId).padEnd(5)} ${oneLine(`${status}${c.command ? `  ${c.command}` : ''}`)}`
        return (
          <Box key={`r-${c.id}`} flexDirection="row">
            <Text color={mark.color}>{mark.glyph}</Text>
            {c.kind === 'share' ? (
              <Text color={KIND_COLOR.share} bold>⇄</Text>
            ) : (
              <Text color={c.confidence === 'uncertain' ? 'yellow' : undefined} dimColor={c.confidence !== 'uncertain'}>{EVIDENCE_MARK[c.confidence]}</Text>
            )}
            <Button key={`c-${c.id}`} plain dimColor={c.kind !== 'share' && c.confidence !== 'observed' && c.status !== 'running' && !networked(c)} label={trunc(rest, width - 3)} onPress={() => navigate($, x => ({ ...x, mode: 'detail', selected: c.id }))} />
          </Box>
        )
      })}
      {pager(page, pages)}
      <Text dimColor wrap="truncate-end">Enter drills in · ~ inferred from command text · ? runs a script, connections unknown · ↳#n seen by the poller under call #n · ⇄ network file share, not web/API</Text>
    </Box>
  )

  function pager(page: number, pages: number) {
    if (pages <= 1) return null
    return (
      <Box flexDirection="row" columnGap={1}>
        <Button key="pg-prev" plain hotkey="p" dimColor={page === 0} label="newer" onPress={() => setView($, x => ({ ...x, page: Math.max(0, page - 1) }))} />
        <Text dimColor>{`page ${page + 1}/${pages}`}</Text>
        <Button key="pg-next" plain hotkey="n" dimColor={page >= pages - 1} label="older" onPress={() => setView($, x => ({ ...x, page: Math.min(pages - 1, page + 1) }))} />
      </Box>
    )
  }
}

/** The connections the list shows under the view's filter and scope, newest first. */
/**
 * `networked`: a local call the poller saw connect, listed with the network
 * rows (and under the shell filter) even while local calls are hidden.
 */
function scoped(all: readonly NetConn[], v: NetView, networked: (c: NetConn) => boolean = () => false): NetConn[] {
  return all
    .filter(c =>
      v.filter === 'all'
        ? v.showLocal === true || c.kind !== 'local' || networked(c)
        : c.kind === v.filter || (v.filter === 'shell' && networked(c)),
    )
    .filter(c => v.promptId === undefined || (c.promptId ?? '') === v.promptId)
    .filter(c => v.host === undefined || c.host === v.host)
    .reverse()
}
