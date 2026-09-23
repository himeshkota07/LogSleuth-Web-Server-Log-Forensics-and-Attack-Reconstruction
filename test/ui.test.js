// End-to-end UI test in headless Edge/Chrome over the DevTools protocol (no extra packages needed).
// Run with:  node test/ui.test.js [--shots]
"use strict";
var cp = require("child_process"), fs = require("fs"), path = require("path"), os = require("os");

var BROWSERS = [
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
];
var exe = BROWSERS.filter(function (p) { return fs.existsSync(p); })[0];
if (!exe) { console.log("No Edge/Chrome found"); process.exit(1); }

var ROOT = path.resolve(__dirname, "..");
var PAGE = process.env.LS_URL || "file:///" + path.join(ROOT, "index.html").replace(/\\/g, "/");
var SHOTS = process.argv.indexOf("--shots") >= 0;
var PORT = 9333;
var profile = fs.mkdtempSync(path.join(os.tmpdir(), "ls-ui-"));
var tmpLog = path.join(profile, "sample.log");

function line(ip, sec, method, url, status, bytes, ua) {
  var h = 10 + Math.floor(sec / 3600), m = Math.floor(sec % 3600 / 60), s = sec % 60;
  var p = function (n) { return (n < 10 ? "0" : "") + n; };
  return ip + " - - [14/Sep/2026:" + p(h) + ":" + p(m) + ":" + p(s) + ' +0530] "' + method + " " + url + ' HTTP/1.1" ' +
    status + " " + bytes + ' "-" "' + (ua || "Mozilla/5.0 (Windows NT 10.0)") + '"';
}
function buildLog() {
  var l = [];
  var pages = ["/", "/products?id=3", "/cart", "/search?q=shoes", "/static/app.js", "/about-us"];
  for (var i = 0; i < 1500; i++) l.push(line("198.51.100." + (i % 50), i * 2, "GET", pages[i % pages.length], 200, 900 + i % 300));
  for (var j = 0; j < 30; j++) l.push(line("203.0.113.10", 600 + j, "GET", "/old" + j, 404, 200, "gobuster/3.6"));
  l.push(line("203.0.113.10", 640, "GET", "/.env", 200, 700, "gobuster/3.6"));
  for (var k = 0; k < 15; k++) l.push(line("203.0.113.20", 900 + k * 3, "POST", "/login", 401, 300));
  l.push(line("203.0.113.20", 960, "POST", "/login", 302, 300));
  l.push(line("203.0.113.20", 970, "GET", "/admin/export", 200, 3 * 1048576));
  // Markup in attacker-controlled fields must be shown as text, never rendered.
  l.push(line("203.0.113.30", 1000, "GET", "/search?q=%3Cscript%3E", 200, 500, '<b id=injected>x</b>'));
  l.push("not a log line at all");
  return l.join("\n");
}
fs.writeFileSync(tmpLog, buildLog());

var browser = cp.spawn(exe, ["--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
  "--remote-debugging-port=" + PORT, "--user-data-dir=" + profile, "--window-size=1366,900", "about:blank"], { stdio: "ignore" });

var ws, nextId = 1, pending = {}, errors = [], passed = 0, failed = 0;
function send(method, params) {
  return new Promise(function (res, rej) {
    var id = nextId++;
    pending[id] = { res: res, rej: rej };
    ws.send(JSON.stringify({ id: id, method: method, params: params || {} }));
  });
}
async function evaluate(expr) {
  var r = await send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error("eval failed: " + JSON.stringify(r.exceptionDetails.exception && r.exceptionDetails.exception.description || r.exceptionDetails.text));
  return r.result.value;
}
var wait = function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };
async function waitFor(expr, timeout) {
  var t0 = Date.now();
  while (Date.now() - t0 < (timeout || 15000)) { if (await evaluate(expr)) return true; await wait(100); }
  throw new Error("timeout waiting for " + expr);
}
async function check(name, fn) {
  try { await fn(); passed++; console.log("  ok   " + name); }
  catch (e) { failed++; console.log("  FAIL " + name + "\n       " + e.message); }
}
function assert(c, msg) { if (!c) throw new Error(msg || "assertion failed"); }
async function shot(name) {
  if (!SHOTS) return;
  var r = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: true });
  fs.mkdirSync(path.join(ROOT, "test", "screenshots"), { recursive: true });
  fs.writeFileSync(path.join(ROOT, "test", "screenshots", name + ".png"), Buffer.from(r.data, "base64"));
}

async function connect() {
  for (var i = 0; i < 50; i++) {
    try {
      var list = await (await fetch("http://127.0.0.1:" + PORT + "/json")).json();
      var pg = list.filter(function (t) { return t.type === "page"; })[0];
      if (pg) return pg.webSocketDebuggerUrl;
    } catch (e) { /* not up yet */ }
    await wait(200);
  }
  throw new Error("browser did not start");
}

(async function main() {
  var url = await connect();
  ws = new WebSocket(url);
  await new Promise(function (r) { ws.onopen = r; });
  ws.onmessage = function (m) {
    var msg = JSON.parse(m.data);
    if (msg.id && pending[msg.id]) {
      if (msg.error) pending[msg.id].rej(new Error(msg.error.message)); else pending[msg.id].res(msg.result);
      delete pending[msg.id];
    } else if (msg.method === "Runtime.exceptionThrown") {
      errors.push(msg.params.exceptionDetails.exception ? msg.params.exceptionDetails.exception.description : msg.params.exceptionDetails.text);
    } else if (msg.method === "Runtime.consoleAPICalled" && (msg.params.type === "error" || msg.params.type === "warning")) {
      errors.push("console." + msg.params.type + ": " + msg.params.args.map(function (a) { return a.value || a.description; }).join(" "));
    } else if (msg.method === "Log.entryAdded" && msg.params.entry.level === "error") {
      errors.push("log: " + msg.params.entry.text + " " + (msg.params.entry.url || ""));
    }
  };
  await send("Runtime.enable"); await send("Log.enable"); await send("Page.enable"); await send("DOM.enable");
  await send("Browser.setDownloadBehavior", { behavior: "allow", downloadPath: profile, eventsEnabled: true }).catch(function () {});
  await send("Page.navigate", { url: PAGE });
  await waitFor("document.readyState === 'complete' && !!window.LogSleuthApp");

  console.log("UI tests (" + path.basename(exe) + ")");
  await check("page loads with scripts and no errors", async function () {
    assert(await evaluate("typeof LSRules === 'object' && typeof LSEngine === 'object'"));
    assert(await evaluate("document.getElementById('results').classList.contains('hidden')"), "results should start hidden");
    assert(errors.length === 0, errors.join("; "));
  });
  await shot("01-start");

  await check("analyse with nothing loaded shows a message, not an error", async function () {
    await evaluate("document.getElementById('analyseBtn').click()");
    assert(/Load or paste/.test(await evaluate("document.getElementById('status').textContent")));
  });

  await check("file upload via file input", async function () {
    var doc = await send("DOM.getDocument");
    var node = await send("DOM.querySelector", { nodeId: doc.root.nodeId, selector: "#fileInput" });
    await send("DOM.setFileInputFiles", { nodeId: node.nodeId, files: [tmpLog] });
    await waitFor("/lines ready from sample.log/.test(document.getElementById('status').textContent)");
    assert(/sample\.log/.test(await evaluate("document.getElementById('fileInfo').textContent")));
  });

  await check("batch analysis completes and fills every section", async function () {
    await evaluate("document.getElementById('analyseBtn').click()");
    await waitFor("/Analysis complete/.test(document.getElementById('status').textContent)");
    var s = await evaluate("JSON.stringify(LogSleuthApp.state.results.summary)");
    s = JSON.parse(s);
    assert(s.parsed === 1549, "parsed " + s.parsed);
    assert(s.unparsed === 1, "unparsed " + s.unparsed);
    assert(s.attackerCount === 3, "attackers " + s.attackerCount);
    assert(await evaluate("document.querySelectorAll('#stats .stat').length") === 6);
    assert(await evaluate("document.querySelectorAll('#timeline rect').length") > 5, "timeline bars");
    assert(await evaluate("document.querySelectorAll('#attackerTable tr[data-ip]').length") === 3);
    assert(await evaluate("document.querySelectorAll('#findingTable tr[data-key]').length") >= 7);
    assert(await evaluate("document.querySelectorAll('#recs .rec').length") >= 6);
    assert(await evaluate("document.querySelectorAll('#feed .item').length") >= 7);
    assert(/skipped/.test(await evaluate("document.getElementById('rangeLine').textContent")));
    var top = await evaluate("document.querySelector('#attackerTable tr[data-ip]').dataset.ip");
    assert(top === "203.0.113.20", "riskiest should be the account-takeover source, got " + top);
  });
  await shot("02-results");

  await check("markup inside log lines is escaped, never rendered", async function () {
    assert(await evaluate("document.getElementById('injected') === null"), "injected element found in DOM");
    await evaluate("document.getElementById('searchBox').value='203.0.113.30'; document.getElementById('searchBox').dispatchEvent(new Event('input'))");
    await evaluate("document.querySelector('#findingTable tr[data-key]').click()");
    assert(await evaluate("/&lt;b id=/.test(document.querySelector('#findingTable .samples').innerHTML)"), "sample not escaped");
    var rep = await evaluate("LogSleuthApp.buildReport(LogSleuthApp.state.results)");
    assert(rep.indexOf('<b id=injected') < 0 && rep.indexOf("&lt;b id=") >= 0, "report not escaped");
  });

  await check("findings filters: severity, search, IP chip, expand/collapse", async function () {
    await evaluate("document.getElementById('searchBox').value=''; document.getElementById('searchBox').dispatchEvent(new Event('input'))");
    var all = await evaluate("document.querySelectorAll('#findingTable tr[data-key]').length");
    await evaluate("var s=document.getElementById('sevFilter'); s.value='Critical'; s.dispatchEvent(new Event('change'))");
    var crit = await evaluate("[...document.querySelectorAll('#findingTable tr[data-key] .badge')].map(b=>b.textContent)");
    assert(crit.length > 0 && crit.length < all && crit.every(function (x) { return x === "Critical"; }), "severity filter: " + crit);
    await evaluate("var s=document.getElementById('sevFilter'); s.value=''; s.dispatchEvent(new Event('change'))");
    await evaluate("document.querySelector('#attackerTable tr[data-ip=\"203.0.113.10\"]').click()");
    var ips = await evaluate("[...document.querySelectorAll('#findingTable tr[data-key]')].map(t=>t.cells[2].textContent)");
    assert(ips.length > 0 && ips.every(function (x) { return x === "203.0.113.10"; }), "ip filter: " + ips);
    assert(!(await evaluate("document.getElementById('ipChip').classList.contains('hidden')")));
    await evaluate("document.querySelector('#findingTable tr[data-key]').click()");
    assert(await evaluate("!!document.querySelector('#findingTable .samples')"), "expand");
    await evaluate("document.querySelector('#findingTable tr[data-key]').click()");
    assert(await evaluate("!document.querySelector('#findingTable .samples')"), "collapse");
    await evaluate("document.getElementById('ipChip').click()");
    assert(await evaluate("document.querySelectorAll('#findingTable tr[data-key]').length") === all);
    await evaluate("document.getElementById('searchBox').value='zzz-no-match'; document.getElementById('searchBox').dispatchEvent(new Event('input'))");
    assert(/No findings match/.test(await evaluate("document.getElementById('findingTable').textContent")));
    await evaluate("document.getElementById('searchBox').value=''; document.getElementById('searchBox').dispatchEvent(new Event('input'))");
  });

  await check("exports download CSV, JSON and HTML", async function () {
    await evaluate("document.getElementById('expCsv').click(); document.getElementById('expJson').click(); document.getElementById('expHtml').click()");
    var t0 = Date.now(), files = [];
    while (Date.now() - t0 < 10000) {
      files = fs.readdirSync(profile).filter(function (f) { return /^logsleuth-.*\.(csv|json|html)$/.test(f); });
      if (files.length === 3) break;
      await wait(200);
    }
    assert(files.length === 3, "downloads: " + files.join(", "));
    var json = JSON.parse(fs.readFileSync(path.join(profile, files.filter(function (f) { return /json$/.test(f); })[0]), "utf8"));
    assert(json.findings.length > 0 && json.summary.parsed === 1549, "json content");
    var csv = fs.readFileSync(path.join(profile, files.filter(function (f) { return /csv$/.test(f); })[0]), "utf8");
    assert(csv.split("\r\n").length === json.findings.length + 1, "csv rows");
  });

  await check("theme toggle switches and re-renders", async function () {
    var before = await evaluate("document.documentElement.getAttribute('data-theme')");
    await evaluate("document.getElementById('themeBtn').click()");
    var after = await evaluate("document.documentElement.getAttribute('data-theme')");
    assert(after && after !== before, before + " -> " + after);
  });
  await shot("03-theme");
  await evaluate("document.getElementById('themeBtn').click()");

  await check("live replay streams alerts and can be stopped", async function () {
    await evaluate("var s=document.getElementById('speedSel'); s.value='2000'");
    await evaluate("document.getElementById('replayBtn').click()");
    assert(await evaluate("document.getElementById('stopBtn').disabled === false"), "stop enabled while running");
    assert(await evaluate("document.getElementById('analyseBtn').disabled === true"), "analyse disabled while running");
    await wait(400);
    await evaluate("document.getElementById('stopBtn').click()");
    var st = await evaluate("document.getElementById('status').textContent");
    assert(/Stopped at line/.test(st), st);
    assert(await evaluate("document.getElementById('analyseBtn').disabled === false"));
  });

  await check("live replay runs to completion with same totals as batch", async function () {
    await evaluate("document.getElementById('replayBtn').click()");
    await waitFor("/Replay complete/.test(document.getElementById('status').textContent)", 20000);
    var s = JSON.parse(await evaluate("JSON.stringify(LogSleuthApp.state.results.summary)"));
    assert(s.parsed === 1549 && s.attackerCount === 3, JSON.stringify(s));
    assert(await evaluate("document.querySelectorAll('#feed .item').length") === s.alertCount, "feed count");
  });

  await check("pasted text replaces the loaded file", async function () {
    await evaluate("var p=document.getElementById('pasteBox'); p.value=" + JSON.stringify(line("192.0.2.1", 1, "GET", "/", 200, 10)) + "; p.dispatchEvent(new Event('input'))");
    assert(/1 line ready \(pasted\)/.test(await evaluate("document.getElementById('status').textContent")));
    await evaluate("document.getElementById('analyseBtn').click()");
    await waitFor("/Analysis complete/.test(document.getElementById('status').textContent)");
    assert(await evaluate("LogSleuthApp.state.results.summary.parsed") === 1);
    assert(/No suspicious sources/.test(await evaluate("document.getElementById('attackerTable').textContent")));
    assert(/No weaknesses/.test(await evaluate("document.getElementById('recs').textContent")));
  });

  await check("unrecognised input explains itself", async function () {
    await evaluate("var p=document.getElementById('pasteBox'); p.value='hello\\nworld'; p.dispatchEvent(new Event('input'))");
    await evaluate("document.getElementById('analyseBtn').click()");
    await waitFor("/Analysis complete/.test(document.getElementById('status').textContent)");
    assert(/None of the 2 lines matched/.test(await evaluate("document.getElementById('rangeLine').textContent")));
  });

  await check("clear resets the page", async function () {
    await evaluate("document.getElementById('clearBtn').click()");
    assert(await evaluate("document.getElementById('results').classList.contains('hidden')"));
    assert(await evaluate("document.getElementById('pasteBox').value === ''"));
  });

  await check("mobile width has no horizontal page scroll", async function () {
    await send("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
    await evaluate("var p=document.getElementById('pasteBox'); p.value=" + JSON.stringify(buildLog()) + "; p.dispatchEvent(new Event('input'))");
    await evaluate("document.getElementById('analyseBtn').click()");
    await waitFor("/Analysis complete/.test(document.getElementById('status').textContent)");
    await wait(200);
    var over = await evaluate("document.documentElement.scrollWidth - window.innerWidth");
    assert(over <= 0, "overflow " + over + "px");
  });
  await shot("04-mobile");

  await check("no JavaScript errors during the whole session", async function () {
    assert(errors.length === 0, errors.join("\n       "));
  });

  console.log("\n" + passed + " passed, " + failed + " failed");
  ws.close();
  browser.kill();
  setTimeout(function () { try { fs.rmSync(profile, { recursive: true, force: true }); } catch (e) { /* locked */ } process.exit(failed ? 1 : 0); }, 800);
})().catch(function (e) {
  console.log("Test harness error: " + e.stack);
  browser.kill();
  process.exit(1);
});
