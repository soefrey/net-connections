import { expect, mock, test } from 'claude-code/testing'

import {
  detectMounts,
  detectShare,
  detectShell,
  detectUncertain,
  driveMounts,
  maskHome,
  PLACEHOLDER_HOSTS,
  parseCimDrives,
  parseMountOutput,
  parseNetUse,
  redact,
} from '../hooks/detect'
import { shortCommand } from '../hooks/poller'

const raw = String.raw

const LINUX_MOUNT = [
  'sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)',
  '/dev/nvme0n1p2 on / type ext4 (rw,relatime)',
  '//fileserver/projects on /mnt/projects type cifs (rw,relatime,vers=3.1.1,username=me)',
  'nas:/export/media on /mnt/media type nfs4 (rw,relatime,vers=4.2)',
  'me@build.example.com:/srv/data on /home/me/remote type fuse.sshfs (rw,nosuid,nodev)',
  'gvfsd-fuse on /run/user/1000/gvfs type fuse.gvfsd-fuse (rw,nosuid,nodev,user_id=1000)',
  'tmpfs on /run/user/1000 type tmpfs (rw,nosuid,nodev)',
].join('\n')

const MAC_MOUNT = [
  '/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)',
  '/dev/disk3s5 on /System/Volumes/Data (apfs, local, journaled, nobrowse)',
  'map auto_home on /System/Volumes/Data/home (autofs, automounted, nobrowse)',
  '//me@fileserver._smb._tcp.local/Team%20Share on /Volumes/Team Share (smbfs, nodev, nosuid, mounted by me)',
  'nas.local:/volume1/backup on /Volumes/backup (nfs, asynchronous)',
  'https://dav.example.com/files on /Volumes/files (webdav, nodev, noexec, nosuid, mounted by me)',
  '/dev/disk4s1 on /Volumes/USB Stick (msdos, local, nodev, nosuid, noowners)',
].join('\n')

test('reads network mounts from Linux and macOS mount output', async () => {
  expect(parseMountOutput(LINUX_MOUNT).map(m => [m.root, m.host, m.protocol])).toEqual([
    ['/mnt/projects', 'fileserver', 'SMB (TCP 445)'],
    ['/mnt/media', 'nas', 'NFS (TCP 2049)'],
    ['/home/me/remote', 'build.example.com', 'SFTP over SSH (TCP 22)'],
    ['/run/user/1000/gvfs', '(per share)', 'gvfs'],
  ])
  expect(parseMountOutput(MAC_MOUNT).map(m => [m.root, m.host, m.protocol])).toEqual([
    ['/Volumes/Team Share', 'fileserver._smb._tcp.local', 'SMB (TCP 445)'],
    ['/Volumes/backup', 'nas.local', 'NFS (TCP 2049)'],
    ['/Volumes/files', 'dav.example.com', 'WebDAV over HTTP(S)'],
  ])
})

test('paths under network mounts are shares, others are not', async () => {
  const linux = parseMountOutput(LINUX_MOUNT)
  expect(detectMounts('cp /mnt/projects/plan.md /tmp/', linux).map(t => t.host)).toEqual(['fileserver'])
  expect(detectMounts('/mnt/projectsX/a', linux)).toHaveLength(0)
  expect(detectMounts('ls /run/user/1000/gvfs/smb-share:server=nas,share=media/films', linux).map(t => [t.host, t.protocol])).toEqual([['nas', 'SMB (TCP 445)']])
  expect(detectMounts('cat /home/me/notes.md', linux)).toHaveLength(0)
  const mac = parseMountOutput(MAC_MOUNT)
  expect(detectMounts('open "/Volumes/Team Share/q3.xlsx"', mac).map(t => t.host)).toEqual(['fileserver._smb._tcp.local'])
  expect(detectMounts('/Volumes/USB Stick/a.txt', mac)).toHaveLength(0)
})

test('reads mapped drives from CIM and from net use in any language', async () => {
  expect(parseCimDrives(raw`Z:|\\fileserver\projects` + '\r\n' + raw`Y:|\\nas\media` + '\r\n')).toEqual({ 'Z:': raw`\\fileserver\projects`, 'Y:': raw`\\nas\media` })
  const german = [
    'Neue Verbindungen werden gespeichert.',
    '',
    'Status       Lokal     Remote                    Netzwerk',
    '-------------------------------------------------------------------------------',
    raw`OK           Z:        \\fileserver\projects     Microsoft Windows Network`,
    raw`Getrennt     Y:        \\nas\media               Microsoft Windows Network`,
    raw`OK                     \\fileserver\IPC$         Microsoft Windows Network`,
    'Der Befehl wurde erfolgreich ausgeführt.',
  ].join('\r\n')
  expect(parseNetUse(german)).toEqual({ 'Z:': raw`\\fileserver\projects`, 'Y:': raw`\\nas\media` })
})

test('paths on mapped drives are shares, local drives are not', async () => {
  const drives = driveMounts({ 'Z:': raw`\\fileserver\projects` })
  expect(detectMounts(raw`Z:\plan\q3.xlsx`, drives).map(t => [t.host, t.url])).toEqual([['fileserver', raw`\\fileserver\projects`]])
  expect(detectMounts('cat /z/plan/q3.md', drives).map(t => t.host)).toEqual(['fileserver'])
  expect(detectMounts('copy z:/a.txt C:/tmp', drives)).toHaveLength(1)
  expect(detectMounts(raw`C:\Users\me\notes.md`, drives)).toHaveLength(0)
})

const PANE = {
  plugin: 'net-connections',
  component: 'Pane',
  requestId: 'net-connections',
  props: { title: 'Network', isFocused: true, bodyColumns: 120, placement: 'dock', scroll: { offset: 0, bodyRows: 38 }, view: {} },
  viewport: { columns: 160, rows: 40 },
} as const

test('reads network targets off shell commands', async () => {
  expect(detectShell('curl -s https://example.com/a?b=1 | jq .').map(t => t.host)).toEqual(['example.com'])
  expect(detectShell('git push origin main').map(t => t.host)).toEqual(['git remote'])
  expect(detectShell('git clone git@github.com:foo/bar.git').map(t => t.host)).toContain('github.com')
  expect(detectShell('npm install left-pad').map(t => t.host)).toEqual(['registry.npmjs.org'])
  expect(detectShell('ls -la && cat README.md')).toHaveLength(0)
})

test('flags commands that run code it cannot see', async () => {
  expect(detectUncertain('python scripts/sync.py --all')).toBeDefined()
  expect(detectUncertain('cd app && ./deploy.sh')).toBeDefined()
  expect(detectUncertain('npm run build')).toBeDefined()
  expect(detectUncertain('node --version')).toBeUndefined()
  expect(detectUncertain('cat hooks/register.ts')).toBeUndefined()
  expect(detectUncertain('ls -la')).toBeUndefined()
})

test('a web fetch shows in the pane, tied to its prompt, and drills down', async ($, on) => {
  mock.clock(on)
  mock.env(on, {})
  on('turn.start', ($, e) => ({ turnId: e.turnId }))
  on('tool.call', { tool: 'Read' }, () => ({ result: { type: 'text' } }))
  on('tool.call', { tool: 'WebFetch' }, () => ({
    result: { bytes: 2048, code: 200, codeText: 'OK', result: 'hi', durationMs: 120, url: 'https://example.com/docs' },
  }))

  await $.turn.start({ text: 'look up the docs', turnId: 'turn-1' })
  await $.tool.call({ tool: 'WebFetch', url: 'https://example.com/docs', prompt: 'summarize' })
  await $.tool.call({ tool: 'Read', file_path: 'C:/notes/todo.md' })

  for (const surface of ['terminal', 'desktop'] as const) {
    const ui = await $.ui.mount({ ...PANE, surface })
    expect(await ui.find({ text: /1 connections/ })).toBeDefined()
    const rows = await ui.findAll({ type: 'Button', text: /example\.com/ })
    expect(rows).toHaveLength(1)
    await ui.press({ key: rows[0]!.key! })
    expect(await ui.find({ text: /HTTP 200 OK/ })).toBeDefined()
    expect(await ui.find({ text: /look up the docs/ })).toBeDefined()
    expect(await ui.find({ type: 'Button', text: /#\s*2 .*todo\.md/ })).toBeUndefined()
    await ui.press({ key: 'back' })
    expect(await ui.find({ type: 'Button', text: /LOCAL .*todo\.md/ })).toBeUndefined()
    await ui.press({ key: 'toggle-local' })
    expect(await ui.find({ type: 'Button', text: /LOCAL .*todo\.md/ })).toBeDefined()
    await ui.press({ key: 'toggle-local' })
    await ui.press({ key: 'v-prompts' })
    expect(await ui.find({ type: 'Button', text: /P1 .*look up the docs/ })).toBeDefined()
    await ui.press({ key: 'v-list' })
    await ui.unmount()
  }
})

test('a Read on a mapped drive shows as a share of its server', async ($, on) => {
  mock.clock(on)
  mock.env(on, { OS: 'Windows_NT' })
  on('turn.start', ($, e) => ({ turnId: e.turnId }))
  on('tool.call', { tool: 'Read' }, () => ({ result: { type: 'text' } }))
  on('process.run', () => ({
    value: {
      exitCode: 0,
      stdout: raw`Z:|\\fileserver\projects` + '\r\n',
      stderr: '',
      isStdoutTruncated: false,
      isStderrTruncated: false,
    },
  }))
  const listed = await $.command.run({ command: 'net', args: 'drives', origin: { kind: 'composer' }, presentation: { isFullscreen: false, columns: 160 } })
  expect(listed.text).toContain(raw`Z: → \\fileserver\projects (SMB (TCP 445))`)

  await $.turn.start({ text: 'open the q3 plan', turnId: 'turn-3' })
  await $.tool.call({ tool: 'Read', file_path: raw`Z:\plan\q3.md` })

  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  const row = await ui.find({ type: 'Button', text: /SHARE .*fileserver/ })
  expect(row).toBeDefined()
  await ui.press({ key: row!.key! })
  expect(await ui.find({ text: /mapped network drive Z:/ })).toBeDefined()
  await ui.press({ key: 'back' })
  await ui.press({ key: 'v-hosts' })
  expect(await ui.find({ text: /Mapped drives: Z: → / })).toBeDefined()
  await ui.unmount()
})

test('on macOS a Read under /Volumes is a share and // paths are not', async ($, on) => {
  mock.clock(on)
  mock.env(on, {})
  on('turn.start', ($, e) => ({ turnId: e.turnId }))
  on('tool.call', { tool: 'Read' }, () => ({ result: { type: 'text' } }))
  on('process.run', ($, e) => ({
    value: { exitCode: e.argv[0] === 'mount' ? 0 : 1, stdout: e.argv[0] === 'mount' ? MAC_MOUNT : '', stderr: '', isStdoutTruncated: false, isStderrTruncated: false },
  }))
  const listed = await $.command.run({ command: 'net', args: 'mounts', origin: { kind: 'composer' }, presentation: { isFullscreen: false, columns: 160 } })
  expect(listed.text).toContain('/Volumes/Team Share → ')

  await $.turn.start({ text: 'open the team plan', turnId: 'turn-4' })
  await $.tool.call({ tool: 'Read', file_path: '/Volumes/Team Share/plan.md' })
  await $.tool.call({ tool: 'Read', file_path: '//etc/hosts' })

  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await ui.find({ type: 'Button', text: /SHARE .*fileserver/ })).toBeDefined()
  expect(await ui.find({ type: 'Button', text: /SHARE .*etc/ })).toBeUndefined()
  await ui.press({ key: 'v-hosts' })
  expect(await ui.find({ text: /Network mounts: \/Volumes\/Team Share → / })).toBeDefined()
  await ui.unmount()
})

test('reads UNC paths as file-share access', async () => {
  expect(detectShare(raw`\\fileserver\projects\plan.docx`).map(t => [t.host, t.protocol])).toEqual([['fileserver', 'SMB (TCP 445)']])
  expect(detectShare(raw`copy a.txt \\nas.local\backup\x`).map(t => t.url)).toEqual([raw`\\nas.local\backup`])
  expect(detectShare('ls //nas/media/films').map(t => t.host)).toEqual(['nas'])
  expect(detectShare(raw`\\dav.example.com@SSL\DavWWWRoot\x`)[0]?.protocol).toBe('WebDAV over HTTPS')
  expect(detectShare(raw`\\?\C:\very\long\path`)).toHaveLength(0)
  expect(detectShare('curl https://example.com/a')).toHaveLength(0)
})

test('a Read on a UNC path is highlighted as a share, not hidden as local', async ($, on) => {
  mock.clock(on)
  mock.env(on, {})
  on('turn.start', ($, e) => ({ turnId: e.turnId }))
  on('tool.call', { tool: 'Read' }, () => ({ result: { type: 'text' } }))

  await $.turn.start({ text: 'read the plan on the server', turnId: 'turn-2' })
  await $.tool.call({ tool: 'Read', file_path: String.raw`\\fileserver\projects\plan.md` })

  for (const surface of ['terminal', 'desktop'] as const) {
    const ui = await $.ui.mount({ ...PANE, surface })
    expect(await ui.find({ text: /⇄ 1 file-share access$/ })).toBeDefined()
    const row = await ui.find({ type: 'Button', text: /SHARE .*fileserver/ })
    expect(row).toBeDefined()
    await ui.press({ key: row!.key! })
    expect(await ui.find({ text: /not a web or API connection/ })).toBeDefined()
    await ui.press({ key: 'back' })
    await ui.unmount()
  }
})

test('a web fetch offers its tool output and the raw page, a long CRLF body in parts', async ($, on) => {
  mock.clock(on)
  mock.env(on, {})
  on('turn.start', ($, e) => ({ turnId: e.turnId }))
  on('tool.call', { tool: 'WebFetch' }, () => ({
    result: { bytes: 30000, code: 200, codeText: 'OK', result: 'the summary', durationMs: 120, url: 'https://example.com/feed' },
  }))
  const body = Array.from({ length: 2000 }, (_, i) => `<entry id="${i}">\tline ${i}\u0007</entry>`).join('\r\n')
  on('http.fetch', () => ({ value: { status: 200, ok: true, headers: { 'content-type': 'application/atom+xml' }, text: body } }))

  await $.turn.start({ text: 'read the feed', turnId: 'turn-1' })
  await $.tool.call({ tool: 'WebFetch', url: 'https://example.com/feed', prompt: 'list it' })

  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  const row = (await ui.findAll({ type: 'Button', text: /example\.com/ }))[0]!
  await ui.press({ key: row.key! })
  expect(await ui.find({ text: /the summary/ })).toBeDefined()
  await ui.press({ key: 'resp-raw' })
  expect(await ui.find({ text: /application\/atom\+xml/ })).toBeDefined()
  expect(await ui.find({ text: /<entry id="0">\tline 0�<\/entry>/ })).toBeDefined()
  expect(await ui.find({ text: /\r/ })).toBeUndefined()
  expect(await ui.find({ text: /part 1\/\d+/ })).toBeDefined()
  await ui.press({ key: 'raw-next' })
  expect(await ui.find({ text: /part 2\/\d+/ })).toBeDefined()
  expect(await ui.find({ type: 'Button', text: /raw response of #1/ })).toBeUndefined()
  await ui.press({ key: 'resp-tool' })
  expect(await ui.find({ text: /the summary/ })).toBeDefined()
  await ui.unmount()
})

test('on Windows a shell call shows the connections its processes made', async ($, on) => {
  mock.clock(on)
  mock.env(on, { OS: 'Windows_NT' })
  on('turn.start', ($, e) => ({ turnId: e.turnId }))
  on('process.run', () => ({ value: { exitCode: 0, stdout: '', stderr: '', isStdoutTruncated: false, isStderrTruncated: false } }))
  const spawned: string[] = []
  on('process.spawn', async function* ($, e) {
    spawned.push(e.input ?? '')
    const start = Number(e.env?.NETCONN_T0) + 5000
    const key = '4242|[2a02::1]:50000|2a02:2e0::85|443'
    const line = (o: object) => ({ stream: 'stdout' as const, text: `${JSON.stringify(o)}\n` })
    yield line({ ev: 'ready', root: 1, rootName: 'claude.exe' })
    yield line({ ev: 'open', key, pid: 4242, name: 'curl.exe', cmd: 'curl.exe -s https://www.heise.de/', addr: '2a02:2e0::85', port: 443, local: '[2a02::1]:50000', top: 4240, topStart: start })
    yield line({ ev: 'names', addr: '2a02:2e0::85', names: ['www.heise.de'] })
    yield line({ ev: 'close', key })
    yield line({ ev: 'end' })
    return { value: { code: 0, signal: null } }
  })
  on('tool.call', { tool: 'Bash' }, () => ({ result: { stdout: 'ok', stderr: '', interrupted: false } }))

  await $.turn.start({ text: 'run the fetch script', turnId: 'turn-1' })
  await $.tool.call({ tool: 'Bash', command: './fetch.sh' })
  await $.tool.call({ tool: 'Bash', command: 'echo done' })

  expect(spawned.length).toBeGreaterThanOrEqual(1)
  expect(spawned[0]).toContain('GetExtendedTcpTable')
  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  // a local call the poller saw nothing for stays hidden; the call it saw connect is listed
  expect(await ui.find({ type: 'Button', text: /echo done/ })).toBeUndefined()
  expect(await ui.find({ type: 'Button', text: /#?\s*1 .*→ 1 seen/ })).toBeDefined()
  const row = await ui.find({ type: 'Button', text: /SHELL .*↳#1 www\.heise\.de/ })
  expect(row).toBeDefined()
  await ui.press({ key: row!.key! })
  expect(await ui.find({ text: /curl\.exe \(PID 4242\) connected; seen in the TCP table/ })).toBeDefined()
  expect(await ui.find({ text: /HTTPS \(TCP 443\)/ })).toBeDefined()
  expect(await ui.find({ text: /Bash call: \.\/fetch\.sh/ })).toBeDefined()
  expect(await ui.find({ text: /closed/ })).toBeDefined()
  expect(await ui.find({ type: 'Button', text: /↑ #1 .*\.\/fetch\.sh/ })).toBeDefined()
  await ui.press({ key: 'parent' })
  expect(await ui.find({ text: /Observed connections of this call \(1\)/ })).toBeDefined()
  expect(await ui.find({ type: 'Button', text: /↳ #\d+ SHELL www\.heise\.de/ })).toBeDefined()
  await ui.unmount()
})

test('masks credentials in commands', async () => {
  expect(redact('curl -H "Authorization: Bearer abcdef123456789" https://api.example.com')).toBe('curl -H "Authorization: Bearer ***" https://api.example.com')
  expect(redact('git clone https://me:hunter2@git.example.com/repo.git')).toBe('git clone https://***:***@git.example.com/repo.git')
  expect(redact('mysql --password=hunter2 -u root')).toBe('mysql --password=*** -u root')
  expect(redact('API_KEY=abc123 node app.js')).toBe('API_KEY=*** node app.js')
  expect(redact('echo ghp_abcdefghijklmnopqrstuvwxyz0123')).toBe('echo ***')
  expect(redact('curl https://example.com/docs?page=2')).toBe('curl https://example.com/docs?page=2')
  expect(redact('12 in / 3 out')).toBe('12 in / 3 out')
})

test('a command with control characters or secrets is recorded clean and still draws', async ($, on) => {
  mock.clock(on)
  mock.env(on, {})
  on('turn.start', ($, e) => ({ turnId: e.turnId }))
  on('tool.call', { tool: 'Bash' }, () => ({ result: { stdout: '\u001b[31mred\u001b[0m', stderr: '', interrupted: false } }))

  await $.turn.start({ text: 'call the api', turnId: 'turn-1' })
  await $.tool.call({ tool: 'Bash', command: 'printf "\u001b[2J\u202e" && curl -H "Authorization: Bearer abcdef123456789" https://api.example.com/v1' })

  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  const row = await ui.find({ type: 'Button', text: /api\.example\.com/ })
  expect(row).toBeDefined()
  expect(row!.text).not.toMatch(/[\u001b\u202e]/)
  expect(row!.text).not.toContain('abcdef123456789')
  await ui.press({ key: row!.key! })
  expect(await ui.find({ text: /Bearer \*\*\*/ })).toBeDefined()
  expect(await ui.find({ text: /abcdef123456789/ })).toBeUndefined()
  await ui.unmount()
})

test('back returns to the view it came from, step by step', async ($, on) => {
  mock.clock(on)
  mock.env(on, {})
  on('turn.start', ($, e) => ({ turnId: e.turnId }))
  on('tool.call', { tool: 'WebFetch' }, () => ({ result: { bytes: 10, code: 200, codeText: 'OK', result: 'hi', durationMs: 5, url: 'https://example.com/' } }))

  await $.turn.start({ text: 'first prompt', turnId: 'turn-1' })
  await $.tool.call({ tool: 'WebFetch', url: 'https://example.com/', prompt: 'a' })
  await $.turn.start({ text: 'second prompt', turnId: 'turn-2' })
  await $.tool.call({ tool: 'WebFetch', url: 'https://example.org/', prompt: 'b' })

  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await ui.find({ key: 'list-back' })).toBeUndefined()
  await ui.press({ key: 'v-prompts' })
  await ui.press({ key: (await ui.find({ type: 'Button', text: /P2 .*second prompt/ }))!.key! })
  expect(await ui.find({ text: /▸ P2: second prompt/ })).toBeDefined()
  await ui.press({ key: (await ui.find({ type: 'Button', text: /example\.org/ }))!.key! })
  expect(await ui.find({ text: /second prompt/ })).toBeDefined()
  await ui.press({ key: 'back' })
  // back in the list as it was: scoped to P2
  expect(await ui.find({ text: /▸ P2: second prompt/ })).toBeDefined()
  await ui.press({ key: 'list-back' })
  // and back in the by-prompt view it was opened from
  expect(await ui.find({ type: 'Button', text: /P1 .*first prompt/ })).toBeDefined()
  expect(await ui.find({ key: 'list-back' })).toBeUndefined()
  await ui.unmount()
})

test('home directories are shown as ~', async () => {
  expect(maskHome(String.raw`C:\Users\someone\AppData\Local\Programs\Python\python.exe x.py`)).toBe(String.raw`~\AppData\Local\Programs\Python\python.exe x.py`)
  expect(maskHome('cat C:/Users/someone/notes.md')).toBe('cat ~/notes.md')
  expect(maskHome('ls /c/Users/someone/repo /home/dev/src /Users/mac/Desktop')).toBe('ls ~/repo ~/src ~/Desktop')
  expect(maskHome('cat /usr/share/doc /homepage/x')).toBe('cat /usr/share/doc /homepage/x')
})

test('poller rows name the program by file name', async () => {
  expect(shortCommand(String.raw`"C:\Program Files\Git\mingw64\bin\curl.exe" -s https://example.com`)).toBe('curl.exe -s https://example.com')
  expect(shortCommand(String.raw`C:\Python313\python.exe check_sites.py`)).toBe('python.exe check_sites.py')
  expect(shortCommand('git-remote-https.exe origin')).toBe('git-remote-https.exe origin')
})

test('placeholder destinations are not counted or listed as hosts', async ($, on) => {
  mock.clock(on)
  mock.env(on, {})
  on('turn.start', ($, e) => ({ turnId: e.turnId }))
  on('tool.call', { tool: 'Bash' }, () => ({ result: { stdout: '', stderr: '', interrupted: false } }))
  on('tool.call', { tool: 'WebFetch' }, () => ({ result: { bytes: 1, code: 200, codeText: 'OK', result: 'x', durationMs: 1, url: 'https://example.com/' } }))

  await $.turn.start({ text: 'go', turnId: 'turn-1' })
  await $.tool.call({ tool: 'WebFetch', url: 'https://example.com/', prompt: 'a' })
  await $.tool.call({ tool: 'Bash', command: 'python check_sites.py' })
  await $.tool.call({ tool: 'Bash', command: 'git pull' })
  expect(PLACEHOLDER_HOSTS.has(detectUncertain('python x.py')!.host)).toBe(true)
  expect(PLACEHOLDER_HOSTS.has(detectShell('git pull')[0]!.host)).toBe(true)

  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await ui.find({ text: / · 1 hosts · / })).toBeDefined()
  await ui.press({ key: 'v-hosts' })
  const rows = (await ui.findAll({ type: 'Button' })).filter(b => /^h-/.test(b.key ?? '')).map(b => b.text)
  expect(rows[0]).toMatch(/example\.com/)
  expect(rows.slice(1).every(t => /unknown \(script\)|git remote/.test(t))).toBe(true)
  expect(await ui.find({ text: /No host named/ })).toBeDefined()
  await ui.unmount()
})

// An in-memory `$.store` the test can read back (`mock.store` keeps its contents to itself).
const memStore = (on: Parameters<typeof mock.clock>[0], entries: Record<string, unknown>) => {
  const data = new Map(Object.entries(entries))
  on('store.get', (_$, e) => ({ value: data.get(e.key) }))
  on('store.set', (_$, e) => (data.set(e.key, e.value), { value: undefined }))
  return data
}

const fetchSetup = (on: Parameters<typeof mock.clock>[0]) => {
  mock.clock(on)
  mock.env(on, {})
  on('turn.start', ($, e) => ({ turnId: e.turnId }))
  on('tool.call', { tool: 'WebFetch' }, () => ({ result: { bytes: 1, code: 200, codeText: 'OK', result: 'x', durationMs: 1, url: 'https://example.com/' } }))
}

test('a host no earlier session used is flagged and remembered across sessions', async ($, on) => {
  fetchSetup(on)
  const data = memStore(on, { knownHosts: ['old.example.org'] })

  await $.turn.start({ text: 'go', turnId: 'turn-1' })
  await $.tool.call({ tool: 'WebFetch', url: 'https://example.com/', prompt: 'a' })

  expect(data.get('knownHosts')).toEqual(['old.example.org', 'example.com'])
  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await ui.find({ text: /★ 1 new host/ })).toBeDefined()
  await ui.unmount()
})

test('a host an earlier session used is not flagged', async ($, on) => {
  fetchSetup(on)
  memStore(on, { knownHosts: ['example.com'] })

  await $.turn.start({ text: 'go', turnId: 'turn-1' })
  await $.tool.call({ tool: 'WebFetch', url: 'https://example.com/', prompt: 'a' })

  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await ui.find({ text: /new host/ })).toBeUndefined()
  await ui.unmount()
})

test('with the option off hosts are remembered but not flagged', { options: { flagNewHosts: false } }, async ($, on) => {
  fetchSetup(on)
  const data = memStore(on, {})

  await $.turn.start({ text: 'go', turnId: 'turn-1' })
  await $.tool.call({ tool: 'WebFetch', url: 'https://example.com/', prompt: 'a' })

  expect(data.get('knownHosts')).toEqual(['example.com'])
  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await ui.find({ text: /new host/ })).toBeUndefined()
  await ui.unmount()
})

test('a host only guessed from command text is not remembered', async ($, on) => {
  mock.clock(on)
  mock.env(on, {})
  on('turn.start', ($, e) => ({ turnId: e.turnId }))
  on('tool.call', { tool: 'Bash' }, () => ({ result: { stdout: '', stderr: '', interrupted: false } }))
  const data = memStore(on, {})

  await $.turn.start({ text: 'go', turnId: 'turn-1' })
  await $.tool.call({ tool: 'Bash', command: 'curl https://guessed.example.net/' })

  expect(data.get('knownHosts') ?? []).not.toContain('guessed.example.net')
})
