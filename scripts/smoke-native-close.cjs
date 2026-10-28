// Own-process native window-close integration. Never attaches to an existing app/profile.
// Requires an interactive Windows user; all PowerShell commands are plain text.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const crypto = require('node:crypto');
const { spawn, execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { performance } = require('node:perf_hooks');
const { chromium } = require(process.env.QUIXI_TEST_PLAYWRIGHT_MODULE || 'playwright-core');
const { version } = require('./version.cjs');
const execute = promisify(execFile);
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const psLiteral = value => "'" + String(value).replaceAll("'", "''") + "'";
const report = { version: 1, appVersion: version, status: 'running', startedAt: new Date().toISOString(), checks: [], jsErrors: [] };
let output;
const began = performance.now();
const nativeType = [
  'using System;',
  'using System.Text;',
  'using System.Runtime.InteropServices;',
  'public static class ReaCloseSmokeNative {',
  '  public delegate bool EnumProc(IntPtr window, IntPtr parameter);',
  '  [DllImport("user32.dll", SetLastError=true)] public static extern bool PostMessage(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);',
  '  [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc callback, IntPtr parameter);',
  '  [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);',
  '  [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr window, StringBuilder name, int maximum);',
  '  [DllImport("user32.dll")] static extern IntPtr GetWindow(IntPtr window, uint relationship);',
  '  [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr window, int identifier);',
  '  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);',
  '  [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowText(IntPtr window, StringBuilder text, int maximum);',
  '  public static string[] DescribeWindows(uint process) {',
  '    var result=new System.Collections.Generic.List<string>();',
  '    EnumWindows((window, parameter) => {',
  '      uint actual; GetWindowThreadProcessId(window, out actual); if(actual!=process) return true;',
  '      var name=new StringBuilder(128); GetClassName(window,name,name.Capacity);',
  '      var text=new StringBuilder(256); GetWindowText(window,text,text.Capacity);',
  '      result.Add(window.ToInt64()+" owner="+GetWindow(window,4).ToInt64()+" class="+name+" title="+text); return true;',
  '    },IntPtr.Zero); return result.ToArray();',
  '  }',
  '  public static IntPtr FindOwnedDialog(uint process, IntPtr owner) {',
  '    IntPtr found=IntPtr.Zero;',
  '    EnumWindows((window, parameter) => {',
  '      uint actual; GetWindowThreadProcessId(window, out actual);',
  '      if(actual!=process || GetWindow(window,4)!=owner) return true;',
  '      var name=new StringBuilder(64); GetClassName(window,name,name.Capacity);',
  '      if(name.ToString()!="#32770") return true;',
  '      found=window; return false;',
  '    },IntPtr.Zero);',
  '    return found;',
  '  }',
  '}'
].join('\n');

async function poll(check, description, timeout = 15000, interval = 600) {
  const until = performance.now() + timeout;
  let last;
  while (performance.now() < until) {
    try { const value = await check(); if (value) return value; } catch (error) { last = error; }
    await delay(interval);
  }
  throw Error(description + ' timed out' + (last ? ': ' + last.message : ''));
}
function listening(port) {
  return new Promise(resolve => {
    const socket = net.createConnection({ host: '127.0.0.1', port });
    let settled = false;
    const finish = value => { if (settled) return; settled = true; socket.destroy(); resolve(value); };
    socket.once('connect', () => finish(true)); socket.once('error', () => finish(false));
    socket.setTimeout(600, () => finish(false));
  });
}
function saveReport() {
  if (!output) return;
  report.durationMs = Math.round(performance.now() - began);
  const serialized = JSON.stringify(report, null, 2);
  fs.writeFileSync(output, serialized);
  const localReport = path.join(report.directory, 'native-close-report.json');
  if (localReport !== output) fs.writeFileSync(localReport, serialized);
}
function passed(name, detail = {}) {
  report.checks.push({ name, status: 'passed', ...detail });
  saveReport();
}
function isAlive(app) { return !app.exited && app.child.exitCode === null && app.child.signalCode === null; }
async function waitExit(app, timeout = 15000) {
  await poll(() => app.exited, 'Owned application exit', timeout);
  assert.equal(app.exitCode, 0, 'The app crashed or was forcibly terminated');
}

function processGuard(app) {
  return [
    "$ErrorActionPreference='Stop'",
    '$appProcess=Get-Process -Id ' + app.child.pid + ' -ErrorAction Stop',
    'if([IO.Path]::GetFullPath($appProcess.Path) -ine ' + psLiteral(app.exe) + "){throw 'Unexpected app process path'}",
    '$startTicks=$appProcess.StartTime.ToUniversalTime().Ticks.ToString()',
    app.startTicks ? 'if($startTicks -ne ' + psLiteral(app.startTicks) + "){throw 'Application PID was reused'}" : '',
    "if($appProcess.SessionId -eq 0){throw 'Native close requires an interactive Windows user session'}"
  ].filter(Boolean);
}
async function runPowerShell(lines) {
  const result = await execute('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', lines.join('\n')],
    { windowsHide: true, timeout: 15000, maxBuffer: 1024 * 1024 });
  return result.stdout.trim() ? JSON.parse(result.stdout.trim()) : null;
}
async function captureIdentity(app) {
  assert(isAlive(app), 'Owned application exited before identity verification');
  const identity = await runPowerShell([...processGuard(app),
    '[pscustomobject]@{startTicks=$startTicks;sessionId=$appProcess.SessionId}|ConvertTo-Json -Compress']);
  assert(isAlive(app), 'Owned application exited during identity verification');
  app.startTicks = identity.startTicks; app.sessionId = identity.sessionId;
}
async function verifyCdpOwner(app, port) {
  assert(app.startTicks, 'Capture owned child identity before connecting');
  const proof = await runPowerShell([...processGuard(app),
    '$owners=@(Get-NetTCPConnection -State Listen -LocalPort ' + port + ' -ErrorAction Stop | Select-Object -ExpandProperty OwningProcess -Unique)',
    "if($owners.Count -eq 0){throw 'The CDP listener is unavailable'}",
    'foreach($ownerPid in $owners){',
    '  $listener=Get-Process -Id $ownerPid -ErrorAction Stop',
    "  if($listener.SessionId -ne $appProcess.SessionId){throw 'CDP belongs to another session'}",
    '  $cursor=[long]$ownerPid; $seen=[Collections.Generic.HashSet[long]]::new()',
    '  while($cursor -ne ' + app.child.pid + '){',
    "    if($cursor -le 0 -or !$seen.Add($cursor)){throw 'CDP listener is not an owned app descendant'}",
    '    $ancestor=Get-CimInstance Win32_Process -Filter ("ProcessId = "+$cursor) -ErrorAction Stop',
    "    if(!$ancestor){throw 'CDP process ancestry disappeared'}",
    '    $cursor=[long]$ancestor.ParentProcessId',
    '  }',
    '}',
    '[pscustomobject]@{listenerPids=@($owners);sessionId=$appProcess.SessionId}|ConvertTo-Json -Compress']);
  assert(isAlive(app), 'Owned app exited while verifying CDP ownership');
  app.cdpProof = proof;
}

async function native(app, action = 'close', button = 0) {
  assert(isAlive(app), 'The owned test application already exited');
  assert(app.startTicks, 'Capture owned child identity before native actions');
  const verify = [...processGuard(app),
    'Add-Type -TypeDefinition @\'',
    nativeType,
    "'@",
    '$mainWindow=$appProcess.MainWindowHandle',
    "if($mainWindow -eq [IntPtr]::Zero){throw 'Owned app window is unavailable'}"
  ];
  if (action === 'close') {
    verify.push("if(![ReaCloseSmokeNative]::PostMessage($mainWindow,0x0010,[IntPtr]::Zero,[IntPtr]::Zero)){throw 'WM_CLOSE could not be posted'}",
      "[pscustomobject]@{sent=$true;startTicks=$startTicks;mainWindow=$mainWindow.ToInt64().ToString()}|ConvertTo-Json -Compress");
  } else {
    assert(app.mainWindow, 'First send WM_CLOSE to record the owned main window');
    verify.push('$dialog=[ReaCloseSmokeNative]::FindOwnedDialog(' + app.child.pid + ',[IntPtr]([long]' + psLiteral(app.mainWindow) + '))',
      '$defaultId=0',
      'if($dialog -ne [IntPtr]::Zero){$defaultId=[int]([ReaCloseSmokeNative]::SendMessage($dialog,0x0400,[IntPtr]::Zero,[IntPtr]::Zero).ToInt64() -band 0xFFFF)}');
    if (button) {
      assert([6, 7].includes(button), 'Only native Yes/No may be clicked');
      verify.push("if($dialog -eq [IntPtr]::Zero){throw 'Owned confirmation dialog is unavailable'}",
        "if($defaultId -ne 7){throw 'Native confirmation does not default to No'}",
        '$button=[ReaCloseSmokeNative]::GetDlgItem($dialog,' + button + ')',
        "if($button -eq [IntPtr]::Zero){throw 'Native confirmation button is missing'}",
        "if(![ReaCloseSmokeNative]::PostMessage($button,0x00F5,[IntPtr]::Zero,[IntPtr]::Zero)){throw 'Could not click native confirmation'}");
    }
    verify.push('[pscustomobject]@{found=($dialog -ne [IntPtr]::Zero);defaultId=$defaultId;startTicks=$startTicks;windows=@([ReaCloseSmokeNative]::DescribeWindows(' + app.child.pid + '))}|ConvertTo-Json -Compress');
  }
  const response = await runPowerShell(verify);
  if (response.mainWindow) app.mainWindow = response.mainWindow;
  return response;
}
async function clickAndExit(app, selector) {
  try { await app.page.locator(selector).click({ noWaitAfter: true }); }
  catch (error) {
    if (!/closed|disconnected/i.test(error.message)) throw error;
  }
  await waitExit(app);
}
async function withApp(label, task, settings) {
  if (settings.phase && settings.phase !== label) return;
  const directory = path.join(settings.root, label);
  const profile = path.join(directory, 'data'), projectDirectory = path.join(directory, 'project');
  fs.mkdirSync(profile, { recursive: true }); fs.mkdirSync(projectDirectory);
  const file = path.join(projectDirectory, 'note.txt'), original = 'Native close fixture: ' + label + '\n';
  fs.writeFileSync(file, original);
  assert.equal(await listening(settings.port), false, 'CDP port is already owned by another process');
  const env = { ...process.env, QUIXI_DATA_DIR: profile, QUIXI_RESOURCES_DIR: settings.resources,
    WEBVIEW2_USER_DATA_FOLDER: path.join(directory, 'webview'), WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: '--remote-debugging-port=' + settings.port,
    QUIXI_DEVTOOLS: '1' };
  const stdout = fs.openSync(path.join(directory, 'app.log'), 'wx');
  const stderr = fs.openSync(path.join(directory, 'app-error.log'), 'wx');
  const child = spawn(settings.exe, [], { cwd: path.dirname(settings.exe), env, windowsHide: false, stdio: ['ignore', stdout, stderr] });
  fs.closeSync(stdout); fs.closeSync(stderr);
  const app = { child, exe: settings.exe, directory, file, original, exited: false, exitCode: null, projectDirectory };

  child.once('exit', (code, signal) => { app.exited = true; app.exitCode = code; app.signal = signal; });
  child.once('error', error => { app.spawnError = error; });
  let browser, phaseError;
  const phaseStarted = performance.now();
  try {
    await captureIdentity(app);
    await poll(async () => {
      if (app.spawnError) throw app.spawnError;
      if (!isAlive(app)) throw Error('Owned application exited during startup');
      try { const r = await fetch(settings.cdp + '/json/version', { signal: AbortSignal.timeout(1000) }); return r.ok; } catch { return false; }
    }, 'CDP readiness', 60000);
    assert(isAlive(app), 'Owned application is not running');
    await verifyCdpOwner(app, settings.port);
    browser = await chromium.connectOverCDP(settings.cdp, { timeout: 15000 });
    app.page = await poll(() => browser.contexts().flatMap(context => context.pages()).find(page => page.url().includes('app.localhost/playground')), 'Owned WebView page', 15000);
    const page = app.page; page.setDefaultTimeout(15000);
    page.on('pageerror', error => report.jsErrors.push({ phase: label, message: error.message }));
    await page.locator('#connection').filter({ hasText: 'Connected' }).waitFor();
    assert.equal(await page.title(), 'REA Studio V' + version + ' · Coding & Reverse Engineering');
    app.pg = (route, data = {}) => page.evaluate(async ({ route, data }) => {
      const response = await fetch('/api/quixi/playground/' + route, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
      const result = await response.json(); if (!response.ok) throw Error(result.error || String(response.status)); return result;
    }, { route, data });
    app.project = await app.pg('project', { path: projectDirectory });
    await page.reload(); await page.locator('#connection').filter({ hasText: 'Connected' }).waitFor();
    await page.locator('#project').selectOption(app.project.id);
    await page.locator('.file-row[title="note.txt"]').click();
    await poll(async () => (await page.locator('#editor').inputValue()) === original, 'Loaded fixture editor contents');
    await page.evaluate(() => {
      window.__nativeCloseSmokeRequests = []; window.__nativeCloseSmokeCancellations = [];
      window.addEventListener('rea-native-close-cancelled', event => window.__nativeCloseSmokeCancellations.push({ ...event.detail }));
      window.addEventListener('rea-native-close-request', event => window.__nativeCloseSmokeRequests.push({ ...event.detail }));
    });
    await task(app);
    assert(app.exited, 'Phase must finish by closing its own app');
  } catch (error) {
    phaseError = error;
    if (isAlive(app)) {
      try {
        app.failureWindows = await native(app, 'dialog');
        report.failureDiagnostics = { phase: label, windows: app.failureWindows,
          events: await app.page.evaluate(() => ({ requests: window.__nativeCloseSmokeRequests, cancellations: window.__nativeCloseSmokeCancellations, suppressed: window.__nativeCloseSmokeSuppressedRequests })) };
      } catch (diagnosticError) { report.diagnosticError = diagnosticError.message; }
    }
    if (app.page && isAlive(app)) { try { await app.page.screenshot({ path: path.join(directory, 'failure.png') }); } catch {} }
    throw error;
  } finally {
    const cleanupErrors = [];
    if (browser) {
      try {
        await Promise.race([browser.close(), delay(3000).then(() => { throw Error('CDP disconnect timed out'); })]);
      } catch (error) { cleanupErrors.push(error.message); }
    }
    if (isAlive(app)) {
      report.forcedCleanup = true;
      try {
        // Recheck executable/start time in the same command before terminating only our child tree.
        // If identity was never captured, refuse destructive cleanup.
        assert(app.startTicks, 'Cannot safely clean up a child without a recorded identity');
        await runPowerShell([...processGuard(app),
          '& taskkill.exe /PID ' + child.pid + ' /T /F | Out-Null',
          "if($LASTEXITCODE -ne 0){throw 'Verified owned child cleanup failed'}"]);
        await poll(() => app.exited, 'Owned child cleanup', 6000);
      } catch (error) { cleanupErrors.push(error.message); }
    }
    try { await poll(() => listening(settings.port).then(value => !value), 'Owned CDP shutdown', 15000); }
    catch (error) { cleanupErrors.push(error.message); }
    if (cleanupErrors.length) {
      report.cleanupErrors ||= []; report.cleanupErrors.push({ phase: label, errors: cleanupErrors });
      saveReport();
      if (!phaseError) throw Error('Native-close cleanup failed: ' + cleanupErrors.join('; '));
    }
  }
  passed(label, { durationMs: Math.round(performance.now() - phaseStarted), profile, exitCode: app.exitCode, cdp: app.cdpProof });

}
async function requestDialog(app) {
  await native(app);
  await app.page.locator('#native-close-dialog').waitFor({ state: 'visible' });
  assert(isAlive(app));
}
(async () => {
  assert.equal(process.platform, 'win32', 'Native-close integration requires Windows');
  const exe = process.env.REA_STUDIO_TEST_EXE, resources = process.env.REA_STUDIO_TEST_RESOURCES, data = process.env.REA_STUDIO_TEST_DATA;
  assert(exe && resources && data, 'Set isolated REA_STUDIO_TEST_EXE, REA_STUDIO_TEST_RESOURCES and REA_STUDIO_TEST_DATA');
  assert(fs.statSync(exe).isFile()); assert(fs.existsSync(path.join(resources, 'playground', 'close-guard.js')));
  const dataRoot = path.resolve(data);
  assert(!/(^|[\\/])\.quixi([\\/]|$)/i.test(dataRoot), 'Do not use the normal .quixi profile for integration tests');
  const url = new URL(process.env.REA_STUDIO_TEST_CDP || 'http://127.0.0.1:9326');
  assert.equal(url.protocol, 'http:'); assert.equal(url.hostname, '127.0.0.1'); assert(url.port && !url.username && !url.password && url.pathname === '/');
  const root = path.join(dataRoot, 'native-close-' + crypto.randomUUID()); fs.mkdirSync(root, { recursive: true });
  output = process.env.REA_STUDIO_NATIVE_CLOSE_REPORT ? path.resolve(process.env.REA_STUDIO_NATIVE_CLOSE_REPORT) : path.join(root, 'native-close-report.json'); fs.mkdirSync(path.dirname(output), { recursive: true }); report.directory = root;
  report.selectedPhase = process.env.REA_STUDIO_NATIVE_CLOSE_PHASE || null;
  const settings = { root, phase: report.selectedPhase, exe: path.resolve(exe), resources: path.resolve(resources), cdp: url.origin, port: Number(url.port) };
  saveReport();
  await withApp('cancel-and-save-conflict', async app => {
    const page = app.page, buffer = 'Unsaved editor buffer survives cancellation.\n';
    await page.evaluate(nonce => window.ipc.postMessage(JSON.stringify({ type: 'rea-close-response', nonce, action: 'close' })), crypto.randomUUID());
    await delay(600); assert(isAlive(app), 'Unsolicited IPC closed the application');
    await page.locator('#editor').fill(buffer); await requestDialog(app);
    await page.evaluate(nonce => window.ipc.postMessage(JSON.stringify({ type: 'rea-close-response', nonce, action: 'close' })), crypto.randomUUID());
    await delay(600); assert(isAlive(app), 'Wrong nonce closed the application');
    const cancelledNonce = await page.evaluate(() => window.__nativeCloseSmokeRequests.at(-1).nonce);
    await page.locator('#native-close-cancel').click();
    await page.locator('#native-close-dialog').waitFor({ state: 'hidden' });
    await page.evaluate(nonce => window.ipc.postMessage(JSON.stringify({ type: 'rea-close-response', nonce, action: 'close' })), cancelledNonce);
    await delay(600); assert(isAlive(app), 'A cancelled nonce was accepted for close');
    assert.equal(await page.locator('#editor').inputValue(), buffer);
    assert.equal(fs.readFileSync(app.file, 'utf8'), app.original);
    const external = app.original + 'A separate writer changed the disk.\n'; fs.writeFileSync(app.file, external);
    await requestDialog(app); await page.locator('#native-close-save').click();
    await page.waitForFunction(() => /changed on disk|conflict/i.test(document.getElementById('native-close-error').textContent));
    assert(isAlive(app), 'A failed save discarded the editor');
    assert.equal(await page.locator('#native-close-dialog').isVisible(), true);
    assert.equal(await page.locator('#editor').inputValue(), buffer);
    assert.equal(fs.readFileSync(app.file, 'utf8'), external);
    await page.locator('#native-close-cancel').click(); await page.locator('#native-close-dialog').waitFor({ state: 'hidden' });
    await requestDialog(app); await clickAndExit(app, '#native-close-discard');
    assert.equal(fs.readFileSync(app.file, 'utf8'), external);
  }, settings);
  await withApp('save-and-close', async app => {
    const expected = 'Saved by the actual native close workflow.\n';
    await app.page.locator('#editor').fill(expected); await requestDialog(app);
    await clickAndExit(app, '#native-close-save');
    assert.equal(fs.readFileSync(app.file, 'utf8'), expected);
  }, settings);
  await withApp('discard-and-close', async app => {
    await app.page.locator('#editor').fill('Discarded test edits.\n'); await requestDialog(app);
    await clickAndExit(app, '#native-close-discard');
    assert.equal(fs.readFileSync(app.file, 'utf8'), app.original);
  }, settings);
  await withApp('clean-close', async app => {
    await native(app); await waitExit(app);
    assert.equal(fs.readFileSync(app.file, 'utf8'), app.original);
  }, settings);
  await withApp('backend-terminal-warning', async app => {
    const job = await app.pg('command-start', { project: app.project.id, command: "Start-Sleep -Seconds 30; Write-Output 'native-close-fixture-finished'" });
    assert(job.job);
    const status = await app.pg('command-poll', { project: app.project.id, job: job.job, offset: 0 });
    assert.equal(status.done, false);
    assert.equal(await app.page.evaluate(() => [...terminals.values()].some(terminal => terminal.job)), false, 'Test must not populate the UI terminal map');
    await requestDialog(app);
    assert.equal(await app.page.evaluate(() => window.__nativeCloseSmokeRequests.at(-1).activeWork), true);
    assert.match(await app.page.locator('#native-close-note').textContent(), /running|active|task|command|check|work/i);
    await app.page.locator('#native-close-cancel').click(); await app.page.locator('#native-close-dialog').waitFor({ state: 'hidden' });
    assert.equal((await app.pg('command-poll', { project: app.project.id, job: job.job, offset: 0 })).done, false);
    await app.pg('command-stop', { project: app.project.id, job: job.job });
    await poll(async () => (await app.pg('command-poll', { project: app.project.id, job: job.job, offset: 0 })).done, 'Owned terminal cancellation', 15000);
    await native(app); await waitExit(app);
  }, settings);
  await withApp('synchronous-command-warning', async app => {
    const started = path.join(app.projectDirectory, 'sync-started.txt');
    const release = path.join(app.projectDirectory, 'sync-release.txt');
    const command = [
      "[IO.File]::WriteAllText((Join-Path (Get-Location).Path 'sync-started.txt'),'started')",
      '$closeFixtureDeadline=[DateTime]::UtcNow.AddSeconds(30)',
      "while(!(Test-Path -LiteralPath '.\\sync-release.txt')){if([DateTime]::UtcNow -ge $closeFixtureDeadline){throw 'Native close fixture release timed out'};Start-Sleep -Milliseconds 100}",
      "[Console]::Write('sync-close-work-complete')"
    ].join(';');
    await app.page.evaluate(({ project, command }) => {
      window.__nativeCloseSyncCommand = { done: false };
      fetch('/api/quixi/playground/command', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ project, command }) })
        .then(async response => { window.__nativeCloseSyncCommand = { done: true, ok: response.ok, result: await response.json() }; })
        .catch(error => { window.__nativeCloseSyncCommand = { done: true, error: error.message }; });
    }, { project: app.project.id, command });
    await poll(() => fs.existsSync(started), 'Actual synchronous command start', 15000);
    assert.equal(await app.page.evaluate(() => [...terminals.values()].some(terminal => terminal.job)), false);
    assert.equal(await app.page.evaluate(() => window.__nativeCloseSyncCommand.done), false);
    await requestDialog(app);
    assert.equal(await app.page.evaluate(() => window.__nativeCloseSmokeRequests.at(-1).activeWork), true);
    assert.match(await app.page.locator('#native-close-note').textContent(), /running.*commands|commands.*running/i);
    await app.page.locator('#native-close-cancel').click(); await app.page.locator('#native-close-dialog').waitFor({ state: 'hidden' });
    assert(isAlive(app)); assert.equal(await app.page.evaluate(() => window.__nativeCloseSyncCommand.done), false);
    fs.writeFileSync(release, 'release\n');
    const completed = await poll(async () => {
      const result = await app.page.evaluate(() => window.__nativeCloseSyncCommand);
      return result.done && result;
    }, 'Actual synchronous command completion', 15000);
    assert.equal(completed.ok, true, completed.error);
    assert.equal(completed.result.exitCode, 0);
    assert.equal(completed.result.stdout, 'sync-close-work-complete');
    await native(app); await waitExit(app);
  }, settings);

  await withApp('native-fallback-no-and-yes', async app => {
    const buffer = 'A missing close acknowledgement must not silently lose this.\n';
    await app.page.locator('#editor').fill(buffer);
    await app.page.evaluate(() => {
      // Suppress delivery of the actual host event, as if the renderer cannot handle it.
      // No close event or host reply is fabricated.
      const original = window.dispatchEvent.bind(window);
      window.__nativeCloseSmokeSuppressedRequests = [];
      const blocked = event => {
        if (event.type === 'rea-native-close-request') {
          window.__nativeCloseSmokeSuppressedRequests.push({ ...event.detail }); return true;
        }
        return original(event);
      };
      window.dispatchEvent = blocked;
      if (window.dispatchEvent !== blocked) throw Error('Native request fault injection was not installed');
    });
    await native(app);
    const first = await poll(async () => { const result = await native(app, 'dialog'); return result.found && result; }, 'Actual native fallback', 20000);
    assert.equal(await app.page.evaluate(() => window.__nativeCloseSmokeSuppressedRequests.length), 1, 'One genuine host request must be suppressed');
    assert.equal(first.defaultId, 7, 'Native confirmation must default to No');
    await native(app, 'dialog', 7);
    await poll(async () => !(await native(app, 'dialog')).found, 'Native No dismissal', 10000);
    assert(isAlive(app)); assert.equal(await app.page.locator('#editor').inputValue(), buffer);
    assert.equal(fs.readFileSync(app.file, 'utf8'), app.original);
    await native(app);
    await poll(async () => (await native(app, 'dialog')).found, 'Second native fallback', 20000);
    await native(app, 'dialog', 6); await waitExit(app);
    assert.equal(fs.readFileSync(app.file, 'utf8'), app.original);
  }, settings);
  assert.equal(report.checks.length, settings.phase ? 1 : 7, 'Every requested phase must execute');
  assert.deepEqual(report.jsErrors, [], 'Unexpected JavaScript page errors');
  assert(!report.forcedCleanup, 'A passing run must not need forced cleanup');
  report.status = 'passed'; report.finishedAt = new Date().toISOString(); saveReport();
  console.log(JSON.stringify(report));
})().catch(async error => {
  report.status = 'failed'; report.error = error.stack || error.message; report.finishedAt = new Date().toISOString(); saveReport();
  console.error(error); if (output) console.error('Native-close report: ' + output); process.exitCode = 1;
});
