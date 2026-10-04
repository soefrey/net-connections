// Reads a shell command for the network endpoints it is likely to reach.
// Nothing here sees a socket: it is the command's text, so every target is
// `inferred` and says which part of the command pointed at the network.

import type { NetMount } from '../types'

export type Target = {
  /** Set when this target is another kind than the call's other targets (a share). */
  kind?: 'share'
  host: string
  url?: string
  protocol: string
  reason: string
}

const URL_RE = /\b((?:https?|wss?|ftp|sftp|ssh|git):\/\/[^\s'"`<>|;)\]]+)/gi
const SCP_RE = /(?:^|\s)(?:[\w.-]+@)?([a-z0-9-]+(?:\.[a-z0-9-]+)+):(?!\/\/)[\w~./-]+/gi

type Rule = {
  test: RegExp
  host: string | ((m: RegExpMatchArray) => string | undefined)
  protocol: string
  reason: string
  /** Only when no URL in the command already names the endpoint. */
  ifNoUrl?: true
}

const RULES: readonly Rule[] = [
  { test: /\b(?:npm|pnpm|yarn)\s+(?:i|install|add|ci|update|upgrade|up|publish|view|info|outdated|audit|dlx|create|exec)\b/i, host: 'registry.npmjs.org', protocol: 'HTTPS', reason: 'npm-family package command' },
  { test: /\b(?:npx|bunx|pnpx)\s/i, host: 'registry.npmjs.org', protocol: 'HTTPS', reason: 'package runner may download the package' },
  { test: /\bbun\s+(?:i|install|add|update|x)\b/i, host: 'registry.npmjs.org', protocol: 'HTTPS', reason: 'bun package command' },
  { test: /\b(?:pip3?|python3?\s+-m\s+pip)\s+(?:install|download)\b|\buv\s+(?:pip\s+install|add|sync|lock)\b|\bpoetry\s+(?:install|add|update|lock)\b|\bpipx\s+(?:install|run)\b/i, host: 'pypi.org', protocol: 'HTTPS', reason: 'Python package command' },
  { test: /\bcargo\s+(?:build|install|fetch|update|add|run|test|check|publish)\b/i, host: 'index.crates.io', protocol: 'HTTPS', reason: 'cargo may fetch crates' },
  { test: /\bgo\s+(?:get|install|mod\s+(?:download|tidy))\b/i, host: 'proxy.golang.org', protocol: 'HTTPS', reason: 'Go module command' },
  { test: /\b(?:gem\s+install|bundle\s+(?:install|update))\b/i, host: 'rubygems.org', protocol: 'HTTPS', reason: 'Ruby gem command' },
  { test: /\b(?:dotnet\s+(?:restore|add\s+\S+\s+package|tool\s+install)|nuget\s+install)\b/i, host: 'api.nuget.org', protocol: 'HTTPS', reason: '.NET package command' },
  { test: /\b(?:mvn|gradlew?)\b/i, host: 'repo.maven.apache.org', protocol: 'HTTPS', reason: 'JVM build may resolve dependencies' },
  { test: /\b(?:docker|podman)\s+(?:pull|push|login|run|build|compose\s+(?:pull|up|build))\b/i, host: 'registry-1.docker.io', protocol: 'HTTPS', reason: 'container registry command' },
  { test: /\bgh\s+[a-z]/i, host: 'api.github.com', protocol: 'HTTPS', reason: 'GitHub CLI' },
  { test: /\bgit\s+(?:clone|fetch|pull|push|ls-remote|remote\s+update|submodule\s+update)\b/i, host: 'git remote', protocol: 'git/HTTPS/SSH', reason: 'git command talks to a remote', ifNoUrl: true },
  { test: /\b(?:winget)\s+(?:install|upgrade|update|search|source)\b/i, host: 'cdn.winget.microsoft.com', protocol: 'HTTPS', reason: 'winget package command' },
  { test: /\b(?:choco)\s+(?:install|upgrade|search)\b/i, host: 'community.chocolatey.org', protocol: 'HTTPS', reason: 'Chocolatey package command' },
  { test: /\bscoop\s+(?:install|update|search)\b/i, host: 'github.com', protocol: 'HTTPS', reason: 'Scoop package command' },
  { test: /\bbrew\s+(?:install|update|upgrade|tap)\b/i, host: 'formulae.brew.sh', protocol: 'HTTPS', reason: 'Homebrew command' },
  { test: /\b(?:apt|apt-get|dnf|yum|apk)\s+(?:install|update|upgrade|add)\b/i, host: 'system package mirror', protocol: 'HTTP(S)', reason: 'system package manager' },
  { test: /(?:^|[;&|(]|\bsudo\s|\btime\s)\s*(?:ssh|scp|sftp|rsync|mosh)\s+(?:-\S+\s+)*(?:[\w.-]+@)?([a-z0-9][\w.-]*)/i, host: m => m[1], protocol: 'SSH', reason: 'remote shell / copy command' },
  { test: /(?:^|[;&|(]|\bsudo\s|\btime\s)\s*(?:ping|nslookup|dig|host|traceroute|tracert|telnet|nc|ncat|whois)\s+(?:-\S+\s+)*([a-z0-9][\w.-]*)/i, host: m => m[1], protocol: 'ICMP/DNS/TCP', reason: 'network diagnostic command' },
  { test: /\b(?:Test-NetConnection|tnc|Resolve-DnsName|Test-Connection)\s+(?:-\w+\s+)*([a-z0-9][\w.-]*)/i, host: m => m[1], protocol: 'TCP/DNS/ICMP', reason: 'PowerShell network cmdlet' },
  { test: /\b(?:curl|wget|Invoke-WebRequest|iwr|Invoke-RestMethod|irm|http|https|xh)\b/i, host: 'unknown host', protocol: 'HTTP(S)', reason: 'HTTP client in command', ifNoUrl: true },
  { test: /\bclaude\s+plugin\s+(?:install|marketplace\s+(?:add|update))\b/i, host: 'github.com', protocol: 'HTTPS', reason: 'plugin install fetches from a marketplace', ifNoUrl: true },
]

/**
 * Host names that stand for a destination the command text does not name:
 * kept on the row, but not counted or listed as hosts.
 */
export const PLACEHOLDER_HOSTS: ReadonlySet<string> = new Set(['unknown (script)', 'unknown host', 'git remote', 'system package mirror', 'local'])

export function hostOf(url: string): string {
  try {
    return new URL(url).host || url
  } catch {
    return url
  }
}

export function protocolOf(url: string): string {
  const scheme = url.split(':')[0]?.toLowerCase() ?? ''
  return scheme === '' ? 'HTTP(S)' : scheme.toUpperCase()
}

// The body of a heredoc is data being written, not a command: its words and URLs connect to nothing.
const HEREDOC_RE = /(<<-?\s*(['"]?)(\w+)\2[^\n]*\n)[\s\S]*?\n[ \t]*\3(?=\s|$)/g

export function detectShell(raw: string): Target[] {
  const command = raw.replace(HEREDOC_RE, '$1')
  const found = new Map<string, Target>()
  const add = (t: Target) => {
    const was = found.get(t.host)
    if (was === undefined) found.set(t.host, t)
    else if (!was.reason.includes(t.reason)) found.set(t.host, { ...was, reason: `${was.reason}; ${t.reason}` })
  }

  for (const m of command.matchAll(URL_RE)) {
    const url = (m[1] ?? "").replace(/[.,]+$/, '')
    add({ host: hostOf(url), url, protocol: protocolOf(url), reason: 'URL in command' })
  }
  if (/\bgit\b/i.test(command)) {
    for (const m of command.matchAll(SCP_RE)) {
      add({ host: m[1] ?? "", protocol: 'SSH', reason: 'git SSH remote in command' })
    }
  }
  const hasUrl = found.size > 0
  for (const rule of RULES) {
    if (rule.ifNoUrl && hasUrl) continue
    const m = command.match(rule.test)
    if (m === null) continue
    const host = typeof rule.host === 'string' ? rule.host : rule.host(m)
    if (host === undefined || host === '' || /^-/.test(host)) continue
    add({ host, protocol: rule.protocol, reason: rule.reason })
  }

  return [...found.values()]
}

// Commands that run code the text does not show: a script, an interpreter, a
// build or test runner. Whatever they connect to is invisible from here.
const SCRIPT_RULES: readonly [RegExp, string][] = [
  [/(?:^|[\s;&|(])(?:python3?|py|node|deno|bun|ruby|perl|php|java|pwsh|powershell|bash|sh|zsh|Rscript|julia)(?:\.exe)?\s+(?!-(?:-?version|V|v|h|-help)\b)\S/i, 'starts an interpreter'],
  [/(?:^|[;&|(])\s*(?:&\s*|\.\s+|source\s+|call\s+)?["']?[\w.:\\/-]*\.(?:sh|ps1|py|js|mjs|cjs|ts|rb|pl|bat|cmd|exe)\b/i, 'runs a script or program file'],
  [/\b(?:go|cargo|dotnet)\s+(?:run|test)\b|\b(?:npm|pnpm|yarn|bun)\s+(?:run|test|start|exec)\b|\b(?:make|cmake|pytest|jest|vitest|mocha|tox|nox)\b/i, 'runs a build, test or task runner'],
  [/\b(?:Start-Process|Invoke-Expression|iex|Invoke-Command|icm|Start-Job)\b/i, 'starts code PowerShell cannot show'],
]

/** A target for a command that may connect through code its text does not show. */
export function detectUncertain(command: string): Target | undefined {
  const reasons = SCRIPT_RULES.filter(([re]) => re.test(command)).map(([, why]) => why)
  if (reasons.length === 0) return undefined
  return { host: 'unknown (script)', protocol: 'unknown', reason: `${reasons.join('; ')}: connections it makes are not visible` }
}

// UNC paths (`\\server\share\…`, or `//server/share/…` as a POSIX shell spells
// one): file access that Windows carries over the network, SMB by default,
// WebDAV for `\\server@SSL\…`. Not an HTTP or API connection.
const UNC_RE = /(?:^|[\s"'=(,;|&>])(?:\\\\|\/\/)([A-Za-z0-9][\w.-]*)(@SSL)?(?:@(\d+))?[\\/]([^\\/\s"'|;&<>]+)/g

export function detectShare(text: string): Target[] {
  const found = new Map<string, Target>()
  for (const m of text.matchAll(UNC_RE)) {
    const server = m[1] ?? ''
    const share = m[4] ?? ''
    if (server === '' || server === '.' || server === '?') continue // \\.\ and \\?\ are local device paths
    const isDav = m[2] !== undefined || m[3] !== undefined
    const key = `${server.toLowerCase()}/${share.toLowerCase()}`
    if (found.has(key)) continue
    found.set(key, {
      host: server,
      url: `\\\\${server}\\${share}`,
      protocol: isDav ? `WebDAV over HTTP${m[2] ? 'S' : ''}${m[3] ? ` (port ${m[3]})` : ''}` : 'SMB (TCP 445)',
      reason: `UNC path to share "${share}" on ${server}`,
    })
  }
  return [...found.values()]
}

// ---------- network drives and mounts ----------

const PROTOCOL_BY_FS: readonly [RegExp, string][] = [
  [/^(?:cifs|smb3?|smbfs)$/i, 'SMB (TCP 445)'],
  [/^nfs\d?$/i, 'NFS (TCP 2049)'],
  [/^afpfs$/i, 'AFP (TCP 548)'],
  [/^(?:webdav|davfs|fuse\.davfs2?)$/i, 'WebDAV over HTTP(S)'],
  [/^(?:fuse\.)?sshfs$/i, 'SFTP over SSH (TCP 22)'],
  [/^(?:ceph|fuse\.ceph(?:-fuse)?)$/i, 'Ceph'],
  [/^(?:glusterfs|fuse\.glusterfs)$/i, 'GlusterFS'],
  [/^fuse\.rclone$/i, 'rclone (remote storage)'],
  [/^9p$/i, '9P'],
]
// FUSE types that mount anything; network only when the source looks remote.
const GENERIC_FUSE = /^(?:macfuse|osxfuse|fuse)$/i
const GVFS = /^fuse\.gvfsd-fuse$/i

/** The host a mount source names: `//user@server/share`, `server:/export`, `user@host:/p`, a URL. */
export function hostOfSource(source: string): string {
  if (/^[a-z][\w+.-]*:\/\//i.test(source)) return hostOf(source)
  return source
    .replace(/^\/\//, '')
    .replace(/^[^@/]*@/, '')
    .replace(/[:/].*$/, '')
    .replace(/;.*$/, '')
}

/** The mapped network drives of a Windows lookup, as mounts. */
export function driveMounts(drives: Readonly<Record<string, string>>): NetMount[] {
  return Object.entries(drives).map(([letter, unc]) => {
    const server = unc.replace(/^\\\\/, '').split('\\')[0] ?? unc
    const dav = /@SSL|@\d+/i.test(server)
    return {
      root: letter.toUpperCase(),
      source: unc,
      host: server.replace(/@.*$/, ''),
      protocol: dav ? `WebDAV over HTTP${/@SSL/i.test(server) ? 'S' : ''}` : 'SMB (TCP 445)',
      fsType: 'drive',
    }
  })
}

/**
 * The network file systems in `mount` output, Linux (`src on /p type T (opts)`)
 * or macOS (`src on /p (T, opts)`). Local disks, pseudo file systems and `/`
 * itself are left out.
 */
export function parseMountOutput(stdout: string): NetMount[] {
  const mounts: NetMount[] = []
  for (const line of stdout.split(/\r?\n/)) {
    const m = line.match(/^(.+?) on (\/.*?) (?:type (\S+) \(|\(([^,)]+))/)
    if (m === null) continue
    const source = m[1] ?? ''
    const root = (m[2] ?? '').replace(/\/+$/, '') || '/'
    const fsType = (m[3] ?? m[4] ?? '').trim()
    if (root === '/') continue
    if (GVFS.test(fsType)) {
      mounts.push({ root, source: 'GNOME gvfs', host: '(per share)', protocol: 'gvfs', fsType })
      continue
    }
    const known = PROTOCOL_BY_FS.find(([re]) => re.test(fsType))
    const remoteFuse = GENERIC_FUSE.test(fsType) && /^[^\s/]+@[^\s:]+:|^[^\s/:]+:\//.test(source)
    if (known === undefined && !remoteFuse) continue
    mounts.push({ root, source, host: hostOfSource(source), protocol: known?.[1] ?? 'SFTP/remote (FUSE)', fsType })
  }
  return mounts
}

// gvfs keeps each share in a directory named like `smb-share:server=nas,share=media`.
const GVFS_PROTOCOL: Record<string, string> = {
  'smb-share': 'SMB (TCP 445)',
  sftp: 'SFTP over SSH (TCP 22)',
  dav: 'WebDAV over HTTP',
  davs: 'WebDAV over HTTPS',
  nfs: 'NFS (TCP 2049)',
  ftp: 'FTP (TCP 21)',
  'afp-volume': 'AFP (TCP 548)',
}

function gvfsTarget(mount: NetMount, rest: string): Target | undefined {
  const dir = rest.split('/')[0] ?? ''
  const m = dir.match(/^([\w-]+):(.*)$/)
  if (m === null) return undefined
  const params = Object.fromEntries((m[2] ?? '').split(',').map(kv => kv.split('=') as [string, string]))
  const host = params.server ?? params.host
  if (host === undefined) return undefined
  return {
    host,
    url: `${mount.root}/${dir}`,
    protocol: GVFS_PROTOCOL[m[1] ?? ''] ?? `gvfs ${m[1]}`,
    reason: `GNOME gvfs mount ${dir}${params.share ? ` (share ${params.share})` : ''}`,
  }
}

// A drive letter in a path: `Z:\…`, `Z:/…`, or `/z/…` as Git Bash spells it.
const DRIVE_RE = /(?:^|[\s"'=(,;|&>])(?:([A-Za-z]):[\\/]|\/([A-Za-z])\/)/g
const PATH_START = /[\s"'=(,;|&>]/
const PATH_END = /[\s"'/|;&<>)]/

/**
 * Targets for paths on network drives or mounts. A drive root (`Z:`) matches
 * its letter in any spelling; a mount point matches as a whole path prefix,
 * spaces included (`/Volumes/Team Share/…`), the longest mount winning.
 */
export function detectMounts(text: string, mounts: readonly NetMount[]): Target[] {
  const found = new Map<string, Target>()
  const drives = new Map(mounts.filter(m => /^[A-Z]:$/.test(m.root)).map(m => [m.root, m]))
  if (drives.size > 0) {
    for (const m of text.matchAll(DRIVE_RE)) {
      const mount = drives.get(`${(m[1] ?? m[2] ?? '').toUpperCase()}:`)
      if (mount === undefined || found.has(mount.root)) continue
      found.set(mount.root, {
        host: mount.host,
        url: mount.source,
        protocol: mount.protocol,
        reason: `mapped network drive ${mount.root} → ${mount.source}`,
      })
    }
  }
  const points = mounts.filter(m => m.root.startsWith('/')).sort((a, b) => b.root.length - a.root.length)
  const claimed: [number, number][] = []
  for (const mount of points) {
    for (let at = text.indexOf(mount.root); at !== -1; at = text.indexOf(mount.root, at + 1)) {
      const end = at + mount.root.length
      const before = at === 0 ? ' ' : text[at - 1] ?? ' '
      const after = text[end] ?? ' '
      if (!PATH_START.test(before) || !PATH_END.test(after)) continue
      if (claimed.some(([s, e]) => at >= s && at < e)) continue // a longer mount already took it
      claimed.push([at, end])
      if (GVFS.test(mount.fsType)) {
        const t = after === '/' ? gvfsTarget(mount, text.slice(end + 1)) : undefined
        if (t !== undefined && !found.has(t.url ?? '')) found.set(t.url ?? '', t)
        continue
      }
      if (found.has(mount.root)) continue
      found.set(mount.root, {
        host: mount.host,
        url: mount.source,
        protocol: mount.protocol,
        reason: `network mount ${mount.root} (${mount.fsType}) → ${mount.source}`,
      })
    }
  }
  return [...found.values()]
}

/** Reads the `Z:|\\server\share` lines the session-start CIM query prints. */
export function parseCimDrives(stdout: string): Record<string, string> {
  const drives: Record<string, string> = {}
  for (const line of stdout.split(/\r?\n/)) {
    const m = line.trim().match(/^([A-Za-z]:)\|(\\\\.+)$/)
    if (m?.[1] && m[2]) drives[m[1].toUpperCase()] = m[2].trim()
  }
  return drives
}

/** Reads `net use` output, whatever the display language: a letter, then a UNC path. */
export function parseNetUse(stdout: string): Record<string, string> {
  const drives: Record<string, string> = {}
  for (const line of stdout.split(/\r?\n/)) {
    const m = line.match(/(?:^|\s)([A-Za-z]:)\s+(\\\\\S+)/)
    if (m?.[1] && m[2]) drives[m[1].toUpperCase()] = m[2]
  }
  return drives
}

// ---------- secrets ----------

// Credentials a command line or tool input may carry: the pane shows commands
// in full, so each is masked before it is kept.
const SECRET_RULES: readonly [RegExp, string][] = [
  // user:password@ in a URL
  [/\b([a-z][\w+.-]*:\/\/)[^\s/@:'"]+:[^\s/@'"]+@/gi, '$1***:***@'],
  // Authorization: Bearer … / Basic … headers
  [/(\bauthorization\s*[:=]\s*(?:bearer|basic|token|digest)?\s*)[^\s'"]+/gi, '$1***'],
  [/(\bbearer\s+)[\w.~+/=-]{8,}/gi, '$1***'],
  // --password x, --token=x, -Password x
  [/(--?(?:password|passwd|pwd|token|api-?key|secret|client-?secret|auth)(?:=|\s+))("[^"]*"|'[^']*'|[^\s'"]+)/gi, '$1***'],
  // PASSWORD=x, api_key: "x", access-token=x
  [/(\b[\w-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s&,;'"]+)/gi, '$1***'],
  // well-known token formats wherever they stand
  [/\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_\w{20,}|sk-(?:ant-)?[\w-]{20,}|xox[abprs]-[\w-]{10,}|AKIA[0-9A-Z]{16}|AIza[\w-]{35}|glpat-[\w-]{20,})\b/g, '***'],
]

/** `text` with the credentials it carries replaced by `***`. */
export function redact(text: string): string {
  return SECRET_RULES.reduce((s, [re, to]) => s.replace(re, to), text)
}

// ---------- home directories ----------

// A user's home directory in a path, as Windows, Git Bash, macOS and Linux spell it.
const HOME_RULES: readonly [RegExp, string][] = [
  [/\b[A-Za-z]:[\\/]Users[\\/][^\\/\s"'<>|:*?]+/gi, '~'],
  [/(^|[\s"'=(:,;|&>])\/(?:[A-Za-z]\/Users|Users|home)\/[^/\s"'<>|:]+/g, '$1~'],
]

/** `text` with home directories shown as `~`, so a recorded path does not name the user. */
export function maskHome(text: string): string {
  return HOME_RULES.reduce((s, [re, to]) => s.replace(re, to), text)
}
