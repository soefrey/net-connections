/**
 * The poller: a PowerShell loop that watches the TCP table for connections of
 * processes Claude Code started (shell calls, scripts, the tools they run) and
 * writes one JSON line per event. The engine reports a Bash or PowerShell call,
 * never what its processes connect to; this is how the pane sees it.
 *
 * Windows only. The table and the process list come from the Win32 API
 * (`GetExtendedTcpTable`, a Toolhelp snapshot), a millisecond or two per look,
 * so the loop looks every 25 ms (about 2% of one core) and catches most
 * connections a short `curl` opens. Missed: one that opens and closes between
 * two looks, and a process whose parent already exited (its line to Claude
 * Code is gone, as for a daemonized child).
 *
 * Lines, one JSON object each:
 * - `ready`: `{ root, rootName }`, the Claude Code process whose descendants it watches
 * - `open`: `{ key, pid, name, cmd, addr, port, local, top, topStart }`; `top` is
 *   the descendant started by Claude Code itself (a shell call's shell), `topStart`
 *   its start in Unix milliseconds
 * - `close`: `{ key }`, the connection left the table
 * - `names`: `{ addr, names }`, the DNS cache's names for an address
 * - `tick`: nothing happened for a while; lets the reader stop the loop
 * - `end`: the time limit ran out
 *
 * Read from standard input (`-Command 'iex ([Console]::In.ReadToEnd())'`), so
 * no quoting of a command line or size limit of the environment touches it.
 * `NETCONN_T0` (Unix ms) is the earliest start of a process it counts,
 * `NETCONN_MAX_MS` how long it runs, `NETCONN_EVERY_MS` the pause between looks.
 */
export const POLL_SCRIPT = String.raw`
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;
public static class NetConnTable {
  [DllImport("iphlpapi.dll")]
  static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int af, int cls, uint reserved);
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  struct Entry { public uint size, usage, pid; public IntPtr heap; public uint module, threads, ppid; public int prio; public uint flags; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string exe; }
  [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool Process32FirstW(IntPtr h, ref Entry e);
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool Process32NextW(IntPtr h, ref Entry e);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  static int Port(int p) { return ((p & 0xFF) << 8) | ((p >> 8) & 0xFF); }
  static bool Remote(IPAddress a, int port) {
    if (port == 0 || IPAddress.IsLoopback(a) || a.Equals(IPAddress.Any) || a.Equals(IPAddress.IPv6Any)) return false;
    if (a.IsIPv4MappedToIPv6 && IPAddress.IsLoopback(a.MapToIPv4())) return false;
    return true;
  }
  // Connections to a remote host, of processes not in skip: "pid|local|remote addr|remote port".
  public static List<string> Rows(HashSet<int> skip) {
    var res = new List<string>();
    foreach (int af in new[] { 2, 23 }) {
      int size = 0;
      GetExtendedTcpTable(IntPtr.Zero, ref size, false, af, 5, 0);
      size += 4096;
      IntPtr buf = Marshal.AllocHGlobal(size);
      try {
        if (GetExtendedTcpTable(buf, ref size, false, af, 5, 0) != 0) continue;
        int n = Marshal.ReadInt32(buf);
        for (int i = 0; i < n; i++) {
          if (af == 2) {
            IntPtr r = buf + 4 + i * 24;
            int pid = Marshal.ReadInt32(r, 20), rp = Port(Marshal.ReadInt32(r, 16));
            if (pid <= 0 || skip.Contains(pid)) continue;
            var ra = new IPAddress((uint)Marshal.ReadInt32(r, 12));
            if (!Remote(ra, rp)) continue;
            res.Add(pid + "|" + new IPAddress((uint)Marshal.ReadInt32(r, 4)) + ":" + Port(Marshal.ReadInt32(r, 8)) + "|" + ra + "|" + rp);
          } else {
            IntPtr r = buf + 4 + i * 56;
            int pid = Marshal.ReadInt32(r, 52), rp = Port(Marshal.ReadInt32(r, 44));
            if (pid <= 0 || skip.Contains(pid)) continue;
            byte[] l = new byte[16], rb = new byte[16];
            Marshal.Copy(r + 24, rb, 0, 16);
            var ra = new IPAddress(rb);
            if (!Remote(ra, rp)) continue;
            Marshal.Copy(r, l, 0, 16);
            res.Add(pid + "|[" + new IPAddress(l) + "]:" + Port(Marshal.ReadInt32(r, 20)) + "|" + ra + "|" + rp);
          }
        }
      } finally { Marshal.FreeHGlobal(buf); }
    }
    return res;
  }
  public static Dictionary<int, string[]> Procs() {
    var res = new Dictionary<int, string[]>();
    IntPtr h = CreateToolhelp32Snapshot(2, 0);
    if (h == IntPtr.Zero || h == new IntPtr(-1)) return res;
    try {
      var e = new Entry();
      e.size = (uint)Marshal.SizeOf(typeof(Entry));
      for (bool ok = Process32FirstW(h, ref e); ok; ok = Process32NextW(h, ref e)) res[(int)e.pid] = new[] { e.ppid.ToString(), e.exe };
    } finally { CloseHandle(h); }
    return res;
  }
}
'@
$t0 = [DateTimeOffset]::FromUnixTimeMilliseconds([int64]$env:NETCONN_T0).LocalDateTime
$maxMs = [int64]$env:NETCONN_MAX_MS
$every = [int]$env:NETCONN_EVERY_MS
if ($every -le 0) { $every = 25 }
if ($maxMs -le 0) { $maxMs = 600000 }
$me = $PID
$procs = [NetConnTable]::Procs()
$root = [int]$procs[$me][0]
$x = $root
for ($hops = 0; $hops -lt 8 -and $procs.ContainsKey($x); $hops++) {
  if ($procs[$x][1] -like 'claude*') { $root = $x; break }
  $x = [int]$procs[$x][0]
}
if ($env:NETCONN_ROOT) { $root = [int]$env:NETCONN_ROOT }
$top = @{}
$skip = New-Object 'System.Collections.Generic.HashSet[int]'
$fresh = $false
function TopOf($id) {
  if ($top.ContainsKey($id)) { return $top[$id] }
  if (-not $procs.ContainsKey($id) -and -not $script:fresh) { $script:procs = [NetConnTable]::Procs(); $script:fresh = $true }
  $r = 0
  if ($procs.ContainsKey($id) -and $id -ne $me) {
    $started = (Get-Process -Id $id).StartTime
    if ($started -and $started -ge $t0) {
      $parent = [int]$procs[$id][0]
      if ($parent -eq $root) { $r = $id } elseif ($parent -ne $id -and $parent -gt 0) { $r = TopOf $parent }
    }
  }
  $top[$id] = $r
  if ($r -eq 0) { [void]$skip.Add($id) }
  return $r
}
$watch = [Diagnostics.Stopwatch]::StartNew()
$lastOut = 0
function Emit($o) { [Console]::Out.WriteLine(($o | ConvertTo-Json -Compress)); $script:lastOut = $watch.ElapsedMilliseconds }
Emit @{ ev = 'ready'; root = $root; rootName = $procs[$root][1] }
$open = @{}
$pending = @{}
$lastDns = 0
while ($watch.ElapsedMilliseconds -lt $maxMs) {
  $fresh = $false
  $now = @{}
  foreach ($row in [NetConnTable]::Rows($skip)) {
    $f = $row.Split('|')
    $procId = [int]$f[0]
    $addr = $f[2]
    $t = TopOf $procId
    if ($t -gt 0) {
      $now[$row] = 1
      if (-not $open.ContainsKey($row)) {
        $open[$row] = 1
        $pending[$addr] = 0
        $cmd = (Get-CimInstance Win32_Process -Filter ('ProcessId=' + $procId) -Property CommandLine).CommandLine
        $topStart = ([DateTimeOffset](Get-Process -Id $t).StartTime).ToUnixTimeMilliseconds()
        Emit @{ ev = 'open'; key = $row; pid = $procId; name = $procs[$procId][1]; cmd = $cmd; addr = $addr; port = [int]$f[3]; local = $f[1]; top = $t; topStart = $topStart }
      }
    }
  }
  foreach ($k in @($open.Keys)) {
    if (-not $now.ContainsKey($k)) { $open.Remove($k); Emit @{ ev = 'close'; key = $k } }
  }
  if ($pending.Count -gt 0 -and $watch.ElapsedMilliseconds - $lastDns -gt 400) {
    $lastDns = $watch.ElapsedMilliseconds
    $cache = @(Get-DnsClientCache)
    foreach ($a in @($pending.Keys)) {
      $names = @($cache | Where-Object { $_.Data -eq $a } | ForEach-Object { $_.Entry } | Select-Object -Unique)
      if ($names.Count -gt 0) { Emit @{ ev = 'names'; addr = $a; names = $names }; $pending.Remove($a) }
      elseif ($pending[$a] -ge 10) { $pending.Remove($a) }
      else { $pending[$a]++ }
    }
  }
  if ($watch.ElapsedMilliseconds - $lastOut -gt 500) { Emit @{ ev = 'tick' } }
  Start-Sleep -Milliseconds $every
}
Emit @{ ev = 'end' }
`

export type PollEvent =
  | { ev: 'ready'; root: number; rootName?: string }
  | { ev: 'open'; key: string; pid: number; name?: string; cmd?: string | null; addr: string; port: number; local: string; top: number; topStart: number }
  | { ev: 'close'; key: string }
  | { ev: 'names'; addr: string; names: string[] }
  | { ev: 'tick' }
  | { ev: 'end' }

/** One line of the poller's output, or undefined for anything else it printed. */
export function parsePollLine(line: string): PollEvent | undefined {
  try {
    const o = JSON.parse(line) as { ev?: unknown }
    return typeof o === 'object' && o !== null && typeof o.ev === 'string' ? (o as PollEvent) : undefined
  } catch {
    return undefined
  }
}

const PORTS: Record<number, string> = {
  21: 'FTP', 22: 'SSH', 25: 'SMTP', 53: 'DNS over TCP', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 389: 'LDAP',
  443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 587: 'SMTP', 636: 'LDAPS', 853: 'DNS over TLS', 993: 'IMAPS',
  995: 'POP3S', 1433: 'SQL Server', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5672: 'AMQP',
  6379: 'Redis', 8080: 'HTTP (8080)', 8443: 'HTTPS (8443)', 9418: 'git', 27017: 'MongoDB',
}

/**
 * A command line with its program named by file name alone
 * (`"C:\Python\python.exe" x.py` → `python.exe x.py`): the folder a program
 * lives in says little in a list and often names the user.
 */
export function shortCommand(cmd: string): string {
  const m = cmd.trim().match(/^(?:"([^"]+)"|(\S+))([\s\S]*)$/)
  if (m === null) return cmd
  const program = m[1] ?? m[2] ?? ''
  return `${program.split(/[\\/]/).pop() ?? program}${m[3] ?? ''}`
}

/** What a remote TCP port usually carries. */
export function portProtocol(port: number): string {
  return `${PORTS[port] ?? 'TCP'} (TCP ${port})`
}
