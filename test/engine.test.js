// Run with:  node test/engine.test.js
"use strict";
var assert = require("assert");
var LS = require("../js/engine.js");
var Rules = require("../js/rules.js");

var passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log("  ok   " + name); }
  catch (e) { failed++; console.log("  FAIL " + name + "\n       " + e.message); }
}

// Build a combined-format line. `sec` is seconds after 10:00:00 IST on 14 Sep 2026.
function line(ip, sec, method, url, status, bytes, ua, ref) {
  var h = 10 + Math.floor(sec / 3600), m = Math.floor(sec % 3600 / 60), s = sec % 60;
  var p = function (n) { return (n < 10 ? "0" : "") + n; };
  return ip + ' - - [14/Sep/2026:' + p(h) + ":" + p(m) + ":" + p(s) + ' +0530] "' + method + " " + url + ' HTTP/1.1" ' +
    status + " " + (bytes == null ? "512" : bytes) + ' "' + (ref || "-") + '" "' + (ua || "Mozilla/5.0 (Windows NT 10.0)") + '"';
}
function run(lines) { var e = new LS.Engine(); lines.forEach(function (l) { e.ingest(l); }); return e.results(); }
function ids(res, ip) { return res.findings.filter(function (f) { return !ip || f.ip === ip; }).map(function (f) { return f.rule.id; }).sort(); }

console.log("Parser");
test("parses combined format fields", function () {
  var e = LS.parseLine(line("192.0.2.1", 5, "GET", "/products?id=4", 200, 1234, "UA/1", "http://x/"));
  assert.strictEqual(e.ip, "192.0.2.1");
  assert.strictEqual(e.method, "GET");
  assert.strictEqual(e.path, "/products");
  assert.strictEqual(e.status, 200);
  assert.strictEqual(e.bytes, 1234);
  assert.strictEqual(e.ua, "UA/1");
  assert.strictEqual(e.referer, "http://x/");
});
test("converts timezone offset to UTC", function () {
  var e = LS.parseLine(line("192.0.2.1", 0, "GET", "/", 200));
  assert.strictEqual(new Date(e.ts).toISOString(), "2026-09-14T04:30:00.000Z");
});
test("parses common format (no referer / UA) and '-' bytes", function () {
  var e = LS.parseLine('192.0.2.7 - bob [14/Sep/2026:10:00:00 +0000] "HEAD / HTTP/1.0" 304 -');
  assert.ok(e);
  assert.strictEqual(e.user, "bob");
  assert.strictEqual(e.bytes, 0);
  assert.strictEqual(e.ua, "");
});
test("parses IPv6 source and escaped quotes in user agent", function () {
  var e = LS.parseLine('2001:db8::1 - - [14/Sep/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 10 "-" "Agent \\"quoted\\" v1"');
  assert.ok(e);
  assert.strictEqual(e.ip, "2001:db8::1");
  assert.strictEqual(e.ua, 'Agent \\"quoted\\" v1');
});
test("rejects garbage and counts it as unparsed", function () {
  var eng = new LS.Engine();
  eng.ingest("this is not a log line");
  eng.ingest("");
  eng.ingest("   ");
  var r = eng.results();
  assert.strictEqual(r.summary.total, 1);
  assert.strictEqual(r.summary.unparsed, 1);
  assert.strictEqual(r.summary.parsed, 0);
});
test("deepDecode handles double encoding and malformed escapes", function () {
  assert.strictEqual(LS.deepDecode("%253Cb%253E"), "<b>");
  assert.strictEqual(LS.deepDecode("a+b"), "a b");
  assert.strictEqual(LS.deepDecode("100%"), "100%");
});

console.log("False positives");
test("ordinary browsing raises no findings", function () {
  var lines = [];
  var pages = ["/", "/products?id=12", "/products?id=7&sort=price", "/cart", "/search?q=running+shoes", "/static/app.js",
    "/static/style.css", "/about-us", "/blog/select-the-right-size", "/checkout?c=IN", "/images/logo.png", "/contact"];
  for (var i = 0; i < 300; i++) {
    lines.push(line("198.51.100." + (i % 40), i * 3, i % 10 ? "GET" : "POST", pages[i % pages.length], i % 25 ? 200 : 404, 800 + i));
  }
  lines.push(line("198.51.100.5", 1000, "POST", "/login", 302, 300));
  lines.push(line("198.51.100.6", 1001, "POST", "/login", 401, 300));
  lines.push(line("198.51.100.6", 1005, "POST", "/login", 302, 300));
  var r = run(lines);
  assert.deepStrictEqual(ids(r), []);
  assert.strictEqual(r.summary.attackerCount, 0);
  assert.strictEqual(r.summary.overallLevel, "None");
});

console.log("Signature rules");
test("flags classic keyword markers per category", function () {
  var cases = [
    ["SQLI", "/item?id=1%20UNION%20SELECT%20name%20FROM%20users"],
    ["XSS", "/search?q=%3Cscript%3E"],
    ["TRAVERSAL", "/view?file=../../etc/passwd"],
    ["SENSITIVE", "/.env"],
    ["SENSITIVE", "/backup/site.zip"],
    ["ADMIN", "/admin/"],
    ["UPLOAD_EXEC", "/uploads/avatar.php"]
  ];
  cases.forEach(function (c, i) {
    var r = run([line("203.0.113." + i, 1, "GET", c[1], 404)]);
    assert.ok(ids(r).indexOf(c[0]) >= 0, c[1] + " should raise " + c[0] + ", got " + ids(r));
  });
});
test("flags scanner user-agent and unusual methods", function () {
  var r = run([line("203.0.113.50", 1, "GET", "/", 200, 100, "Mozilla/5.00 (Nikto/2.5.0)"),
               line("203.0.113.51", 1, "TRACE", "/", 405, 100)]);
  assert.deepStrictEqual(ids(r, "203.0.113.50"), ["SCANNER"]);
  assert.deepStrictEqual(ids(r, "203.0.113.51"), ["BAD_METHOD"]);
});
test("does not flag the same rule twice in the alert feed", function () {
  var r = run([line("203.0.113.9", 1, "GET", "/.env", 404), line("203.0.113.9", 2, "GET", "/.git/config", 404)]);
  assert.strictEqual(r.findings.length, 1);
  assert.strictEqual(r.findings[0].count, 2);
  assert.strictEqual(r.alerts.length, 1);
});

console.log("Behaviour rules");
test("directory brute force needs 20 x 404 inside 60 s", function () {
  var slow = [], fast = [];
  for (var i = 0; i < 25; i++) slow.push(line("203.0.113.20", i * 5, "GET", "/p" + i, 404));   // 25 in 120 s: never 20 per 60 s
  for (var j = 0; j < 25; j++) fast.push(line("203.0.113.21", j, "GET", "/p" + j, 404));
  assert.deepStrictEqual(ids(run(slow)), []);
  assert.deepStrictEqual(ids(run(fast)), ["DIR_BRUTE"]);
});
test("login brute force then success raises account takeover", function () {
  var l = [];
  for (var i = 0; i < 12; i++) l.push(line("203.0.113.30", i * 2, "POST", "/login", 401, 300));
  l.push(line("203.0.113.30", 30, "POST", "/login", 302, 300));
  var r = run(l);
  assert.deepStrictEqual(ids(r), ["ACCOUNT_TAKEOVER", "LOGIN_BRUTE"]);
  var ato = r.findings.filter(function (f) { return f.rule.id === "ACCOUNT_TAKEOVER"; })[0];
  assert.ok(/12 failed/.test(ato.detail), ato.detail);
});
test("a few failed logins then success is not a takeover", function () {
  var l = [];
  for (var i = 0; i < 3; i++) l.push(line("203.0.113.31", i, "POST", "/login", 401, 300));
  l.push(line("203.0.113.31", 10, "POST", "/login", 302, 300));
  assert.deepStrictEqual(ids(run(l)), []);
});
test("large responses trigger exfiltration (single and cumulative)", function () {
  var single = run([line("203.0.113.40", 1, "GET", "/export", 200, 3 * 1048576)]);
  assert.deepStrictEqual(ids(single), ["EXFIL"]);
  var cum = [];
  for (var i = 0; i < 12; i++) cum.push(line("203.0.113.41", i, "GET", "/report?page=" + i, 200, 600 * 1024));
  var r = run(cum);
  assert.deepStrictEqual(ids(r), ["EXFIL"]);
  assert.strictEqual(r.findings[0].count, 1, "cumulative exfil should be flagged once");
  var failedBig = run([line("203.0.113.42", 1, "GET", "/export", 500, 3 * 1048576)]);
  assert.deepStrictEqual(ids(failedBig), [], "error responses are not exfiltration");
});
test("request-rate rule fires above 120 req / 60 s", function () {
  var l = [];
  for (var i = 0; i < 130; i++) l.push(line("203.0.113.60", Math.floor(i / 3), "GET", "/", 200, 100));
  assert.ok(ids(run(l)).indexOf("RATE") >= 0);
});

console.log("Scoring and results");
test("risk score grows with kill-chain progress and is capped at 100", function () {
  var l = [line("203.0.113.70", 1, "GET", "/admin/", 404)];
  var low = run(l).attackers[0];
  for (var i = 0; i < 25; i++) l.push(line("203.0.113.70", 2 + i, "GET", "/x" + i, 404, 100, "sqlmap/1.8"));
  l.push(line("203.0.113.70", 40, "GET", "/uploads/a.php?cmd=id", 200));
  l.push(line("203.0.113.70", 50, "GET", "/backup/db.sql", 200, 4 * 1048576));
  var high = run(l).attackers[0];
  assert.ok(high.score > low.score);
  assert.ok(high.score <= 100);
  assert.strictEqual(high.level, "Critical");
  assert.ok(high.phases.indexOf("Actions on Objectives") >= 0);
});
test("findings sorted by severity, recommendations de-duplicated", function () {
  var r = run([line("203.0.113.80", 1, "GET", "/admin/", 200), line("203.0.113.81", 2, "GET", "/admin/", 200),
               line("203.0.113.80", 3, "GET", "/.env", 200)]);
  assert.strictEqual(r.findings[0].rule.severity, "High");
  assert.strictEqual(r.recommendations.length, 2);
  var adm = r.recommendations.filter(function (x) { return x.rule.id === "ADMIN"; })[0];
  assert.strictEqual(adm.ipCount, 2);
});
test("empty input yields a safe empty result", function () {
  var r = new LS.Engine().results();
  assert.strictEqual(r.summary.parsed, 0);
  assert.deepStrictEqual(r.timeline, []);
  assert.strictEqual(r.summary.overallRisk, 0);
});
test("every rule has complete metadata", function () {
  Rules.SIGNATURE_RULES.concat(Rules.BEHAVIOUR_RULES).forEach(function (r) {
    ["id", "name", "severity", "owasp", "mitre", "cwe", "phase", "remediation"].forEach(function (k) {
      assert.ok(r[k], r.id + " missing " + k);
    });
    assert.ok(Rules.KILL_CHAIN.indexOf(r.phase) >= 0, r.id + " has unknown phase");
    assert.ok(Rules.SEVERITY_WEIGHT[r.severity], r.id + " has unknown severity");
  });
});
test("handles 100k lines quickly", function () {
  var l = [];
  for (var i = 0; i < 100000; i++) l.push(line("198.51.100." + (i % 200), Math.floor(i / 30), "GET", "/products?id=" + (i % 90), 200, 900));
  var t0 = Date.now();
  var r = run(l);
  var ms = Date.now() - t0;
  assert.strictEqual(r.summary.parsed, 100000);
  assert.ok(ms < 8000, "took " + ms + " ms");
  console.log("       (" + ms + " ms)");
});

console.log("\n" + passed + " passed, " + failed + " failed");
process.exit(failed ? 1 : 0);
