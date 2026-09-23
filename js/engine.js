/*
 * LogSleuth - Detection engine
 * Parses Apache/Nginx "combined" access-log lines and runs signature + behavioural
 * detections incrementally, so the same engine powers batch analysis and live monitoring.
 */
(function (root) {
  "use strict";

  var Rules = (typeof module !== "undefined" && module.exports) ? require("./rules.js") : root.LSRules;

  // 203.0.113.9 - - [14/Sep/2026:10:15:32 +0530] "GET /x HTTP/1.1" 200 512 "ref" "ua"
  var LINE_RE = /^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+)(?: (HTTP\/[\d.]+))?" (\d{3}) (\d+|-)(?: "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)")?/;
  var MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
  var LOGIN_RE = /(\/login|\/signin|\/sign-in|\/auth|\/wp-login\.php|\/account\/login|\/api\/login|\/session)(\/|\?|$)/i;

  var WINDOW_404 = 60 * 1000, LIMIT_404 = 20;
  var WINDOW_LOGIN = 5 * 60 * 1000, LIMIT_LOGIN = 10, TAKEOVER_MIN_FAILS = 5;
  var WINDOW_RATE = 60 * 1000, LIMIT_RATE = 120;
  var EXFIL_SINGLE = 1024 * 1024, EXFIL_TOTAL = 5 * 1024 * 1024;
  var MAX_SAMPLES = 5;

  function parseTime(s) {
    // 14/Sep/2026:10:15:32 +0530
    var m = /^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?/.exec(s);
    if (!m) return NaN;
    var utc = Date.UTC(+m[3], MONTHS[m[2]], +m[1], +m[4], +m[5], +m[6]);
    if (m[7]) {
      var sign = m[7][0] === "-" ? -1 : 1;
      var off = sign * (parseInt(m[7].substr(1, 2), 10) * 60 + parseInt(m[7].substr(3, 2), 10));
      utc -= off * 60000;
    }
    return utc;
  }

  // Attackers double/triple-encode payloads to dodge naive filters, so decode repeatedly.
  function deepDecode(s) {
    var prev = s || "";
    for (var i = 0; i < 3; i++) {
      var next;
      try { next = decodeURIComponent(prev.replace(/\+/g, " ")); } catch (e) { next = prev.replace(/\+/g, " "); }
      if (next === prev) break;
      prev = next;
    }
    return prev;
  }

  function parseLine(line) {
    var m = LINE_RE.exec(line);
    if (!m) return null;
    var rawUrl = m[5];
    var decoded = deepDecode(rawUrl);
    var q = decoded.indexOf("?");
    return {
      raw: line,
      ip: m[1],
      user: m[2],
      timeText: m[3],
      ts: parseTime(m[3]),
      method: m[4].toUpperCase(),
      rawUrl: rawUrl,
      url: decoded,
      path: q >= 0 ? decoded.slice(0, q) : decoded,
      protocol: m[6] || "",
      status: parseInt(m[7], 10),
      bytes: m[8] === "-" ? 0 : parseInt(m[8], 10),
      referer: deepDecode(m[9] && m[9] !== "-" ? m[9] : ""),
      ua: m[10] && m[10] !== "-" ? m[10] : ""
    };
  }

  function pruneWindow(arr, now, windowMs) {
    while (arr.length && now - arr[0] > windowMs) arr.shift();
  }

  function Engine() { this.reset(); }

  Engine.prototype.reset = function () {
    this.total = 0;
    this.parsed = 0;
    this.unparsed = 0;
    this.bytes = 0;
    this.firstTs = Infinity;
    this.lastTs = -Infinity;
    this.statusClass = { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0 };
    this.ips = {};
    this.findings = {};
    this.alerts = [];
    this.minutes = {};          // epoch-minute -> { total, malicious }
    this.maliciousRequests = 0;
    this.paths = {};
  };

  Engine.prototype._ip = function (e) {
    var p = this.ips[e.ip];
    if (!p) {
      p = this.ips[e.ip] = {
        ip: e.ip, requests: 0, bytes: 0, first: e.ts, last: e.ts,
        status: {}, uas: {}, rules: {}, phases: {}, malicious: 0,
        w404: [], wReq: [], wFail: [], fails: 0, successAfterFail: 0,
        exfilTotalFlagged: false
      };
    }
    return p;
  };

  Engine.prototype._flag = function (rule, e, profile, detail) {
    var key = rule.id + "|" + e.ip;
    var f = this.findings[key];
    var isNew = !f;
    if (isNew) {
      f = this.findings[key] = {
        key: key, rule: rule, ip: e.ip, count: 0, first: e.ts, last: e.ts, samples: [], detail: detail || ""
      };
    }
    f.count++;
    f.last = e.ts;
    if (detail) f.detail = detail;
    if (f.samples.length < MAX_SAMPLES) f.samples.push(e.raw);
    profile.rules[rule.id] = (profile.rules[rule.id] || 0) + 1;
    profile.phases[rule.phase] = true;
    if (isNew || rule.id === "ACCOUNT_TAKEOVER") {
      var alert = { ts: e.ts, timeText: e.timeText, ip: e.ip, rule: rule, detail: detail || e.method + " " + e.url, raw: e.raw };
      this.alerts.push(alert);
      return alert;
    }
    return null;
  };

  // Feed one log line; returns { entry, alerts } where alerts are newly raised this line.
  Engine.prototype.ingest = function (line) {
    var out = { entry: null, alerts: [] };
    if (!line || !line.trim()) return out;
    this.total++;
    var e = parseLine(line.trim());
    if (!e || isNaN(e.ts)) { this.unparsed++; return out; }
    this.parsed++;
    out.entry = e;

    var self = this;
    var p = this._ip(e);
    p.requests++; p.bytes += e.bytes; p.last = e.ts;
    p.status[e.status] = (p.status[e.status] || 0) + 1;
    if (e.ua) p.uas[e.ua] = true;
    this.bytes += e.bytes;
    if (e.ts < this.firstTs) this.firstTs = e.ts;
    if (e.ts > this.lastTs) this.lastTs = e.ts;
    var sc = Math.floor(e.status / 100) + "xx";
    if (this.statusClass[sc] !== undefined) this.statusClass[sc]++;
    this.paths[e.path] = (this.paths[e.path] || 0) + 1;

    var hit = false;
    function raise(rule, detail) {
      hit = true;
      var a = self._flag(rule, e, p, detail);
      if (a) out.alerts.push(a);
    }

    // 1. Signature rules
    Rules.SIGNATURE_RULES.forEach(function (rule) {
      var matched = false;
      if (rule.test) matched = rule.test(e);
      else {
        for (var i = 0; i < rule.fields.length && !matched; i++) {
          var v = e[rule.fields[i]];
          if (v && rule.pattern.test(v)) matched = true;
        }
      }
      if (matched) raise(rule);
    });

    // 2. Behavioural rules (per-IP sliding windows)
    var R = Rules.ruleById;
    p.wReq.push(e.ts); pruneWindow(p.wReq, e.ts, WINDOW_RATE);
    if (p.wReq.length > LIMIT_RATE) raise(R("RATE"), p.wReq.length + " requests in the last 60 s");

    if (e.status === 404) {
      p.w404.push(e.ts); pruneWindow(p.w404, e.ts, WINDOW_404);
      if (p.w404.length >= LIMIT_404) raise(R("DIR_BRUTE"), p.w404.length + " not-found responses in the last 60 s");
    }

    if (e.method === "POST" && LOGIN_RE.test(e.path)) {
      if (e.status === 401 || e.status === 403) {
        p.fails++;
        p.wFail.push(e.ts); pruneWindow(p.wFail, e.ts, WINDOW_LOGIN);
        if (p.wFail.length >= LIMIT_LOGIN) raise(R("LOGIN_BRUTE"), p.wFail.length + " failed logins in 5 min (" + p.fails + " total)");
      } else if ((e.status === 200 || e.status === 302 || e.status === 303) && p.fails >= TAKEOVER_MIN_FAILS) {
        p.successAfterFail++;
        raise(R("ACCOUNT_TAKEOVER"), "Login succeeded after " + p.fails + " failed attempts");
        p.fails = 0;
      }
    }

    if ((e.status === 200 || e.status === 206) && e.bytes > EXFIL_SINGLE) {
      raise(R("EXFIL"), (e.bytes / 1048576).toFixed(2) + " MB returned for " + e.path);
    } else if (!p.exfilTotalFlagged && p.bytes > EXFIL_TOTAL) {
      p.exfilTotalFlagged = true;
      raise(R("EXFIL"), (p.bytes / 1048576).toFixed(2) + " MB served to this IP in total");
    }

    // 3. Timeline bucket
    var minute = Math.floor(e.ts / 60000);
    var b = this.minutes[minute] || (this.minutes[minute] = { total: 0, malicious: 0 });
    b.total++;
    if (hit) { b.malicious++; p.malicious++; this.maliciousRequests++; }
    e.malicious = hit;
    return out;
  };

  Engine.prototype.ingestText = function (text) {
    var lines = text.split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) this.ingest(lines[i]);
    return this.results();
  };

  function riskOf(profile) {
    var score = 0;
    for (var id in profile.rules) {
      var r = Rules.ruleById(id);
      score += Rules.SEVERITY_WEIGHT[r.severity] + Math.min(5, Math.floor(Math.log(profile.rules[id]) * 2));
    }
    // Attackers that progress further along the kill chain are more dangerous.
    var reach = 0;
    Rules.KILL_CHAIN.forEach(function (ph, i) { if (profile.phases[ph]) reach = Math.max(reach, i); });
    score += reach * 2;
    return Math.min(100, score);
  }

  function levelOf(score) {
    if (score >= 70) return "Critical";
    if (score >= 40) return "High";
    if (score >= 15) return "Medium";
    if (score > 0) return "Low";
    return "None";
  }

  Engine.prototype.results = function () {
    var self = this;
    var sevOrder = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

    var findings = Object.keys(this.findings).map(function (k) { return self.findings[k]; })
      .sort(function (a, b) {
        return (sevOrder[a.rule.severity] - sevOrder[b.rule.severity]) || (a.first - b.first);
      });

    var attackers = Object.keys(this.ips).map(function (ip) {
      var p = self.ips[ip];
      var score = riskOf(p);
      return {
        ip: ip, requests: p.requests, bytes: p.bytes, first: p.first, last: p.last,
        malicious: p.malicious, rules: p.rules, uas: Object.keys(p.uas),
        phases: Rules.KILL_CHAIN.filter(function (ph) { return p.phases[ph]; }),
        score: score, level: levelOf(score)
      };
    }).filter(function (a) { return a.score > 0; })
      .sort(function (a, b) { return b.score - a.score || b.malicious - a.malicious; });

    var bySeverity = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    var byOwasp = {}, byRule = {};
    findings.forEach(function (f) {
      bySeverity[f.rule.severity] = (bySeverity[f.rule.severity] || 0) + 1;
      byOwasp[f.rule.owasp] = (byOwasp[f.rule.owasp] || 0) + f.count;
      byRule[f.rule.name] = (byRule[f.rule.name] || 0) + f.count;
    });

    var minuteKeys = Object.keys(this.minutes).map(Number).sort(function (a, b) { return a - b; });
    var timeline = minuteKeys.map(function (m) {
      return { t: m * 60000, total: self.minutes[m].total, malicious: self.minutes[m].malicious };
    });

    // Recommendations: one per triggered rule, ordered by severity, with the evidence count.
    var recs = {};
    findings.forEach(function (f) {
      var r = recs[f.rule.id] || (recs[f.rule.id] = { rule: f.rule, ips: {}, count: 0 });
      r.ips[f.ip] = true; r.count += f.count;
    });
    var recommendations = Object.keys(recs).map(function (k) {
      var r = recs[k];
      return { rule: r.rule, ipCount: Object.keys(r.ips).length, count: r.count };
    }).sort(function (a, b) { return sevOrder[a.rule.severity] - sevOrder[b.rule.severity] || b.count - a.count; });

    var overall = attackers.length ? attackers[0].score : 0;

    return {
      summary: {
        total: this.total, parsed: this.parsed, unparsed: this.unparsed, bytes: this.bytes,
        firstTs: this.firstTs, lastTs: this.lastTs, uniqueIps: Object.keys(this.ips).length,
        maliciousRequests: this.maliciousRequests, attackerCount: attackers.length,
        findingCount: findings.length, alertCount: this.alerts.length,
        statusClass: this.statusClass, overallRisk: overall, overallLevel: levelOf(overall)
      },
      findings: findings,
      attackers: attackers,
      bySeverity: bySeverity,
      byOwasp: byOwasp,
      byRule: byRule,
      timeline: timeline,
      alerts: this.alerts.slice(),
      recommendations: recommendations
    };
  };

  var api = { Engine: Engine, parseLine: parseLine, deepDecode: deepDecode, parseTime: parseTime, levelOf: levelOf };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.LSEngine = api;
})(this);
