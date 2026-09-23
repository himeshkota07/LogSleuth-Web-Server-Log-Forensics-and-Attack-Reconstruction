/*
 * LogSleuth - User interface
 * Log content is untrusted, so every value placed into the page goes through esc().
 */
(function () {
  "use strict";

  var Rules = window.LSRules, LS = window.LSEngine;
  var $ = function (id) { return document.getElementById(id); };

  var state = {
    text: "",          // log text from the file or paste box
    source: "",        // label for the report
    engine: null,
    results: null,
    running: false,
    replayTimer: null,
    lines: null,
    pos: 0,
    ipFilter: "",
    openFinding: null
  };

  var SEV_ORDER = ["Critical", "High", "Medium", "Low"];
  var SEV_COLOR = { Critical: "var(--critical)", High: "var(--high)", Medium: "var(--medium)", Low: "var(--low)", None: "var(--benign)" };

  // ---------- helpers ----------
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function fmtNum(n) { return (n || 0).toLocaleString("en-IN"); }
  function plural(n, word) { return fmtNum(n) + " " + word + (n === 1 ? "" : "s"); }
  function fmtBytes(b) {
    if (!b) return "0 B";
    var u = ["B", "KB", "MB", "GB", "TB"], i = 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return (i ? b.toFixed(1) : b) + " " + u[i];
  }
  function fmtTime(ts) {
    if (!isFinite(ts)) return "-";
    return new Date(ts).toISOString().replace("T", " ").slice(0, 19) + " UTC";
  }
  function fmtDuration(ms) {
    if (!isFinite(ms) || ms < 0) return "-";
    var s = Math.round(ms / 1000);
    var d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
    if (d) return d + "d " + h + "h";
    if (h) return h + "h " + m + "m";
    if (m) return m + "m " + (s % 60) + "s";
    return s + "s";
  }
  function badge(sev) { return '<span class="badge sev-' + esc(sev) + '">' + esc(sev) + "</span>"; }
  function setStatus(msg) { $("status").textContent = msg; }
  function download(name, mime, content) {
    var blob = new Blob([content], { type: mime });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }
  function stamp() { return new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-"); }

  // ---------- theme ----------
  (function initTheme() {
    var saved = null;
    try { saved = localStorage.getItem("logsleuth-theme"); } catch (e) { /* storage unavailable */ }
    if (saved === "light" || saved === "dark") document.documentElement.setAttribute("data-theme", saved);
    $("themeBtn").addEventListener("click", function () {
      var cur = document.documentElement.getAttribute("data-theme");
      if (!cur) cur = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
      var next = cur === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      try { localStorage.setItem("logsleuth-theme", next); } catch (e) { /* ignore */ }
      if (state.results) renderTimeline(state.results);
    });
  })();

  // ---------- input ----------
  var drop = $("drop"), fileInput = $("fileInput");
  drop.addEventListener("click", function () { if (!state.running) fileInput.click(); });
  drop.addEventListener("keydown", function (e) {
    if ((e.key === "Enter" || e.key === " ") && !state.running) { e.preventDefault(); fileInput.click(); }
  });
  ["dragenter", "dragover"].forEach(function (ev) {
    drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.add("over"); });
  });
  ["dragleave", "drop"].forEach(function (ev) {
    drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.remove("over"); });
  });
  drop.addEventListener("drop", function (e) {
    if (state.running) return;
    var f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) readFile(f);
  });
  fileInput.addEventListener("change", function () {
    if (fileInput.files[0]) readFile(fileInput.files[0]);
    fileInput.value = "";
  });
  $("pasteBox").addEventListener("input", function () {
    // Typing into the box takes priority over a previously loaded file.
    state.text = "";
    state.source = "";
    $("fileInfo").textContent = "";
    updateInputStatus();
  });

  function readFile(f) {
    var reader = new FileReader();
    setStatus("Reading " + f.name + "...");
    reader.onload = function () {
      state.text = String(reader.result || "");
      state.source = f.name;
      $("pasteBox").value = "";
      $("fileInfo").textContent = f.name + " (" + fmtBytes(f.size) + ")";
      updateInputStatus();
    };
    reader.onerror = function () { setStatus("Could not read " + f.name + "."); };
    reader.readAsText(f);
  }

  function currentText() {
    if (state.text) return state.text;
    return $("pasteBox").value;
  }

  function updateInputStatus() {
    var t = currentText();
    if (!t.trim()) { setStatus("No log loaded."); return; }
    var n = t.split(/\r?\n/).filter(function (l) { return l.trim(); }).length;
    setStatus(plural(n, "line") + " ready" + (state.source ? " from " + state.source : " (pasted)") + ".");
  }

  function setRunning(on) {
    state.running = on;
    $("analyseBtn").disabled = on;
    $("replayBtn").disabled = on;
    $("clearBtn").disabled = on;
    $("pasteBox").disabled = on;
    $("stopBtn").disabled = !on;
    $("progress").style.display = on ? "block" : "none";
  }
  function setProgress(done, total) {
    $("progress").firstElementChild.style.width = (total ? Math.min(100, done / total * 100) : 0) + "%";
  }

  function prepare() {
    var t = currentText();
    if (!t.trim()) {
      setStatus("Load or paste a log first.");
      return false;
    }
    state.lines = t.split(/\r?\n/);
    state.pos = 0;
    state.engine = new LS.Engine();
    state.ipFilter = "";
    state.openFinding = null;
    $("sevFilter").value = "";
    $("searchBox").value = "";
    $("feed").innerHTML = "";
    $("results").classList.remove("hidden");
    return true;
  }

  // ---------- batch analysis (chunked so large files don't freeze the page) ----------
  $("analyseBtn").addEventListener("click", function () {
    if (state.running || !prepare()) return;
    setRunning(true);
    var CHUNK = 5000;
    (function step() {
      if (!state.running) return;
      var end = Math.min(state.lines.length, state.pos + CHUNK);
      for (; state.pos < end; state.pos++) state.engine.ingest(state.lines[state.pos]);
      setProgress(state.pos, state.lines.length);
      setStatus("Analysing... " + fmtNum(state.pos) + " / " + fmtNum(state.lines.length) + " lines");
      if (state.pos < state.lines.length) setTimeout(step, 0);
      else finish("Analysis complete");
    })();
  });

  // ---------- live replay ----------
  $("replayBtn").addEventListener("click", function () {
    if (state.running || !prepare()) return;
    setRunning(true);
    renderAll();
    var TICK = 100;
    var perTick = Math.max(1, Math.round(parseInt($("speedSel").value, 10) * TICK / 1000));
    var lastRender = 0;
    state.replayTimer = setInterval(function () {
      var end = Math.min(state.lines.length, state.pos + perTick);
      var fresh = [];
      for (; state.pos < end; state.pos++) {
        var r = state.engine.ingest(state.lines[state.pos]);
        if (r.alerts.length) fresh = fresh.concat(r.alerts);
      }
      if (fresh.length) prependAlerts(fresh);
      setProgress(state.pos, state.lines.length);
      setStatus("Live replay... " + fmtNum(state.pos) + " / " + fmtNum(state.lines.length) + " lines");
      var now = Date.now();
      if (now - lastRender > 700) { lastRender = now; renderAll(true); }
      if (state.pos >= state.lines.length) finish("Replay complete");
    }, TICK);
  });

  $("speedSel").addEventListener("change", function () {
    // Speed applies to the next replay; keep it simple and predictable.
    if (state.running && state.replayTimer) setStatus("New speed applies to the next replay.");
  });

  $("stopBtn").addEventListener("click", function () {
    if (state.running) finish("Stopped at line " + fmtNum(state.pos));
  });

  $("clearBtn").addEventListener("click", function () {
    if (state.running) return;
    state.text = ""; state.source = ""; state.engine = null; state.results = null;
    $("pasteBox").value = "";
    $("fileInfo").textContent = "";
    $("results").classList.add("hidden");
    setStatus("No log loaded.");
  });

  function finish(msg) {
    if (state.replayTimer) { clearInterval(state.replayTimer); state.replayTimer = null; }
    setRunning(false);
    renderAll();
    var s = state.results.summary;
    setStatus(msg + ": " + fmtNum(s.parsed) + " requests parsed" +
      (s.unparsed ? ", " + plural(s.unparsed, "line") + " skipped (unrecognised format)" : "") +
      ", " + plural(s.findingCount, "finding") + ".");
  }

  // ---------- rendering ----------
  function renderAll(live) {
    state.results = state.engine.results();
    var r = state.results;
    renderStats(r);
    if (!live) renderFeed(r.alerts);
    $("alertCount").textContent = "(" + fmtNum(r.alerts.length) + ")";
    renderTimeline(r);
    renderSeverity(r);
    renderOwasp(r);
    renderAttackers(r);
    renderFindings();
    renderRecs(r);
  }

  function renderStats(r) {
    var s = r.summary;
    var cards = [
      [fmtNum(s.parsed), "Requests analysed"],
      [fmtNum(s.uniqueIps), "Unique source IPs"],
      [fmtNum(s.maliciousRequests), "Flagged requests"],
      [fmtNum(s.attackerCount), "Suspicious sources"],
      [fmtNum(s.findingCount), "Findings"],
      ['<span style="color:' + SEV_COLOR[s.overallLevel] + '">' + s.overallRisk + "</span><small style=\"font-size:13px;color:var(--muted)\"> /100</small>", "Peak risk (" + esc(s.overallLevel) + ")"]
    ];
    $("stats").innerHTML = cards.map(function (c) {
      return '<div class="stat"><div class="v">' + c[0] + '</div><div class="l">' + c[1] + "</div></div>";
    }).join("");
    $("rangeLine").textContent = s.parsed
      ? "Log window: " + fmtTime(s.firstTs) + " to " + fmtTime(s.lastTs) + " (" + fmtDuration(s.lastTs - s.firstTs) + "), " +
        fmtBytes(s.bytes) + " served. Status codes: 2xx " + fmtNum(s.statusClass["2xx"]) + ", 3xx " + fmtNum(s.statusClass["3xx"]) +
        ", 4xx " + fmtNum(s.statusClass["4xx"]) + ", 5xx " + fmtNum(s.statusClass["5xx"]) + "." +
        (s.unparsed ? " " + plural(s.unparsed, "line") + (s.unparsed === 1 ? " was" : " were") + " not in a recognised log format and skipped." : "")
      : (s.total ? "None of the " + fmtNum(s.total) + " lines matched the Apache/Nginx common or combined log format." : "");
  }

  function alertHtml(a, fresh) {
    return '<div class="item' + (fresh ? " fresh" : "") + '">' +
      '<span class="mono">' + esc(fmtTime(a.ts)) + "</span>" +
      "<span>" + badge(a.rule.severity) + "</span>" +
      '<span class="mono">' + esc(a.ip) + "</span>" +
      "<span><strong>" + esc(a.rule.name) + "</strong><br><span class=\"meta-line mono\">" + esc(truncate(a.detail, 160)) + "</span></span></div>";
  }
  function truncate(s, n) { s = String(s || ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; }

  var FEED_MAX = 300;
  function renderFeed(alerts) {
    var list = alerts.slice(-FEED_MAX).reverse();
    $("feed").innerHTML = list.length ? list.map(function (a) { return alertHtml(a, false); }).join("")
      : '<div class="empty">No alerts raised.</div>';
  }
  function prependAlerts(alerts) {
    var feed = $("feed");
    var empty = feed.querySelector(".empty");
    if (empty) empty.remove();
    var html = alerts.slice().reverse().map(function (a) { return alertHtml(a, true); }).join("");
    feed.insertAdjacentHTML("afterbegin", html);
    while (feed.children.length > FEED_MAX) feed.removeChild(feed.lastChild);
  }

  function renderTimeline(r) {
    var el = $("timeline");
    var pts = r.timeline;
    if (!pts.length) { el.innerHTML = '<p class="hint">No timestamped requests.</p>'; return; }
    // Re-bucket into at most 120 bins so long logs stay readable.
    var start = pts[0].t, end = pts[pts.length - 1].t + 60000;
    var BINS = Math.min(120, Math.max(1, Math.round((end - start) / 60000)));
    var width = (end - start) / BINS;
    var bins = [];
    for (var i = 0; i < BINS; i++) bins.push({ t: start + i * width, total: 0, malicious: 0 });
    pts.forEach(function (p) {
      var idx = Math.min(BINS - 1, Math.floor((p.t - start) / width));
      bins[idx].total += p.total; bins[idx].malicious += p.malicious;
    });
    var max = Math.max.apply(null, bins.map(function (b) { return b.total; })) || 1;
    var W = 1000, H = 220, L = 44, B = 26, T = 10, R = 8;
    var cw = (W - L - R) / BINS;
    var bw = Math.max(1, cw * 0.8);
    var y = function (v) { return T + (H - T - B) * (1 - v / max); };
    var svg = ['<svg viewBox="0 0 ' + W + " " + H + '" preserveAspectRatio="none" role="img" aria-label="Requests per time bucket">'];
    [0, 0.5, 1].forEach(function (f) {
      var v = Math.round(max * f), yy = y(v);
      svg.push('<line x1="' + L + '" x2="' + (W - R) + '" y1="' + yy + '" y2="' + yy + '" stroke="var(--border)" stroke-width="1"/>');
      svg.push('<text x="' + (L - 6) + '" y="' + (yy + 4) + '" text-anchor="end" font-size="11" fill="var(--muted)">' + v + "</text>");
    });
    bins.forEach(function (b, i) {
      var x = L + i * cw + (cw - bw) / 2;
      var tip = esc(fmtTime(b.t) + ": " + b.total + " requests, " + b.malicious + " flagged");
      if (b.total) svg.push('<rect x="' + x + '" y="' + y(b.total) + '" width="' + bw + '" height="' + (y(0) - y(b.total)) + '" fill="var(--benign)"><title>' + tip + "</title></rect>");
      if (b.malicious) svg.push('<rect x="' + x + '" y="' + y(b.malicious) + '" width="' + bw + '" height="' + (y(0) - y(b.malicious)) + '" fill="var(--malicious)"><title>' + tip + "</title></rect>");
    });
    svg.push('<text x="' + L + '" y="' + (H - 6) + '" font-size="11" fill="var(--muted)">' + esc(fmtTime(start)) + "</text>");
    svg.push('<text x="' + (W - R) + '" y="' + (H - 6) + '" font-size="11" text-anchor="end" fill="var(--muted)">' + esc(fmtTime(end)) + "</text>");
    svg.push("</svg>");
    el.innerHTML = svg.join("");
  }

  function barsHtml(rows, colorFn) {
    if (!rows.length) return '<p class="hint">Nothing detected.</p>';
    var max = Math.max.apply(null, rows.map(function (r) { return r[1]; })) || 1;
    return rows.map(function (r) {
      return '<div class="bar-row"><span class="bar-label" title="' + esc(r[0]) + '">' + esc(r[0]) + "</span>" +
        '<span class="track"><span class="fill" style="display:block;width:' + (r[1] / max * 100) + "%;background:" + colorFn(r[0]) + '"></span></span>' +
        '<span class="num">' + fmtNum(r[1]) + "</span></div>";
    }).join("");
  }
  function renderSeverity(r) {
    var rows = SEV_ORDER.map(function (s) { return [s, r.bySeverity[s] || 0]; });
    var any = rows.some(function (x) { return x[1]; });
    $("sevBars").innerHTML = any ? barsHtml(rows, function (s) { return SEV_COLOR[s]; }) : '<p class="hint">Nothing detected.</p>';
  }
  function renderOwasp(r) {
    var rows = Object.keys(r.byOwasp).map(function (k) { return [k, r.byOwasp[k]]; })
      .sort(function (a, b) { return b[1] - a[1]; });
    $("owaspBars").innerHTML = barsHtml(rows, function () { return "var(--accent)"; });
  }

  function renderAttackers(r) {
    var t = $("attackerTable");
    if (!r.attackers.length) { t.innerHTML = '<tr><td class="hint">No suspicious sources found.</td></tr>'; return; }
    var head = "<thead><tr><th>Source IP</th><th>Risk</th><th>Level</th><th class=\"num\">Requests</th><th class=\"num\">Flagged</th><th>Kill-chain stages reached</th><th>Active</th><th>User-Agent</th></tr></thead>";
    var rows = r.attackers.slice(0, 200).map(function (a) {
      var chain = Rules.KILL_CHAIN.map(function (ph) {
        return '<span class="' + (a.phases.indexOf(ph) >= 0 ? "on" : "") + '">' + esc(ph) + "</span>";
      }).join("");
      return '<tr class="clickable" data-ip="' + esc(a.ip) + '" tabindex="0">' +
        '<td class="mono">' + esc(a.ip) + "</td>" +
        '<td><div class="risk"><span class="track"><span class="fill" style="display:block;width:' + a.score + "%;background:" + SEV_COLOR[a.level] + '"></span></span><b>' + a.score + "</b></div></td>" +
        "<td>" + badge(a.level) + "</td>" +
        '<td class="num">' + fmtNum(a.requests) + "</td>" +
        '<td class="num">' + fmtNum(a.malicious) + "</td>" +
        '<td><div class="chain">' + chain + "</div></td>" +
        '<td class="mono">' + esc(fmtTime(a.first).slice(11, 19)) + " to " + esc(fmtTime(a.last).slice(11, 19)) + "<br><span class=\"meta-line\">" + esc(fmtDuration(a.last - a.first)) + "</span></td>" +
        '<td class="mono" title="' + esc(a.uas.join("\n")) + '">' + esc(truncate(a.uas[0] || "-", 40)) + (a.uas.length > 1 ? " (+" + (a.uas.length - 1) + ")" : "") + "</td></tr>";
    }).join("");
    t.innerHTML = head + "<tbody>" + rows + "</tbody>";
    if (r.attackers.length > 200) t.insertAdjacentHTML("beforeend", '<tr><td colspan="8" class="hint">Showing the 200 riskiest of ' + fmtNum(r.attackers.length) + " sources. Export for the full list.</td></tr>");
  }

  $("attackerTable").addEventListener("click", function (e) {
    var tr = e.target.closest("tr[data-ip]");
    if (tr) setIpFilter(tr.getAttribute("data-ip"));
  });
  $("attackerTable").addEventListener("keydown", function (e) {
    var tr = e.target.closest("tr[data-ip]");
    if (tr && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); setIpFilter(tr.getAttribute("data-ip")); }
  });
  function setIpFilter(ip) {
    state.ipFilter = ip;
    renderFindings();
    $("findingTable").scrollIntoView({ behavior: "smooth", block: "start" });
  }
  $("ipChip").addEventListener("click", function () { state.ipFilter = ""; renderFindings(); });
  $("sevFilter").addEventListener("change", renderFindings);
  $("searchBox").addEventListener("input", renderFindings);

  function filteredFindings() {
    if (!state.results) return [];
    var sev = $("sevFilter").value;
    var q = $("searchBox").value.trim().toLowerCase();
    return state.results.findings.filter(function (f) {
      if (sev && f.rule.severity !== sev) return false;
      if (state.ipFilter && f.ip !== state.ipFilter) return false;
      if (q) {
        var hay = (f.ip + " " + f.rule.name + " " + f.rule.owasp + " " + f.rule.mitre + " " + f.rule.cwe + " " + f.rule.phase).toLowerCase();
        if (hay.indexOf(q) < 0) return false;
      }
      return true;
    });
  }

  function renderFindings() {
    var chip = $("ipChip");
    if (state.ipFilter) { chip.textContent = "IP: " + state.ipFilter + "  ✕"; chip.classList.remove("hidden"); }
    else chip.classList.add("hidden");
    var list = filteredFindings();
    var total = state.results ? state.results.findings.length : 0;
    $("findingCount").textContent = list.length === total ? fmtNum(total) + " findings" : fmtNum(list.length) + " of " + fmtNum(total) + " findings";
    var t = $("findingTable");
    if (!list.length) { t.innerHTML = '<tr><td class="hint">' + (total ? "No findings match the filter." : "No findings.") + "</td></tr>"; return; }
    var head = "<thead><tr><th>Severity</th><th>Attack type</th><th>Source IP</th><th class=\"num\">Hits</th><th>OWASP</th><th>MITRE ATT&amp;CK</th><th>CWE</th><th>First seen</th></tr></thead>";
    var MAX = 500;
    var rows = list.slice(0, MAX).map(function (f) {
      var open = state.openFinding === f.key;
      var main = '<tr class="clickable" data-key="' + esc(f.key) + '" tabindex="0" aria-expanded="' + open + '">' +
        "<td>" + badge(f.rule.severity) + "</td>" +
        "<td>" + esc(f.rule.name) + (f.detail ? '<div class="meta-line">' + esc(f.detail) + "</div>" : "") + "</td>" +
        '<td class="mono">' + esc(f.ip) + "</td>" +
        '<td class="num">' + fmtNum(f.count) + "</td>" +
        "<td>" + esc(f.rule.owasp) + "</td>" +
        "<td>" + esc(f.rule.mitre) + "</td>" +
        "<td>" + esc(f.rule.cwe) + "</td>" +
        '<td class="mono">' + esc(fmtTime(f.first)) + "</td></tr>";
      if (!open) return main;
      return main + '<tr><td colspan="8">' +
        '<div class="meta-line">Kill-chain phase: <b>' + esc(f.rule.phase) + "</b>" +
        (f.rule.threshold ? " | Trigger: " + esc(f.rule.threshold) : "") +
        " | Last seen: " + esc(fmtTime(f.last)) + "</div>" +
        '<div class="samples">' + f.samples.map(esc).join("\n") + "</div>" +
        '<div class="meta-line" style="margin-top:8px"><b>Fix:</b> ' + esc(f.rule.remediation) + "</div></td></tr>";
    }).join("");
    t.innerHTML = head + "<tbody>" + rows + "</tbody>";
    if (list.length > MAX) t.insertAdjacentHTML("beforeend", '<tr><td colspan="8" class="hint">Showing ' + MAX + " of " + fmtNum(list.length) + ". Narrow the filter or export to CSV.</td></tr>");
  }

  function toggleFinding(key) {
    state.openFinding = state.openFinding === key ? null : key;
    renderFindings();
  }
  $("findingTable").addEventListener("click", function (e) {
    var tr = e.target.closest("tr[data-key]");
    if (tr) toggleFinding(tr.getAttribute("data-key"));
  });
  $("findingTable").addEventListener("keydown", function (e) {
    var tr = e.target.closest("tr[data-key]");
    if (tr && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); toggleFinding(tr.getAttribute("data-key")); }
  });

  function renderRecs(r) {
    if (!r.recommendations.length) { $("recs").innerHTML = '<p class="hint">No weaknesses detected in this log.</p>'; return; }
    $("recs").innerHTML = r.recommendations.map(function (x, i) {
      return '<div class="rec ' + esc(x.rule.severity) + '"><div class="t">' + (i + 1) + ". " + esc(x.rule.name) + " " + badge(x.rule.severity) + "</div>" +
        '<div class="m">' + esc(x.rule.owasp) + " | " + esc(x.rule.mitre) + " | " + esc(x.rule.cwe) + " | " +
        fmtNum(x.count) + " hits from " + fmtNum(x.ipCount) + " source" + (x.ipCount === 1 ? "" : "s") + "</div>" +
        "<div>" + esc(x.rule.remediation) + "</div></div>";
    }).join("");
  }

  // ---------- export ----------
  function needResults() {
    if (!state.results) { setStatus("Run an analysis first."); return false; }
    return true;
  }

  function csvCell(v) {
    var s = String(v == null ? "" : v);
    // Neutralise spreadsheet formula injection from attacker-controlled log text.
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return '"' + s.replace(/"/g, '""') + '"';
  }

  $("expCsv").addEventListener("click", function () {
    if (!needResults()) return;
    var head = ["severity", "attack_type", "source_ip", "hits", "owasp", "mitre", "cwe", "kill_chain_phase", "first_seen_utc", "last_seen_utc", "detail", "remediation", "sample"];
    var lines = [head.join(",")].concat(state.results.findings.map(function (f) {
      return [f.rule.severity, f.rule.name, f.ip, f.count, f.rule.owasp, f.rule.mitre, f.rule.cwe, f.rule.phase,
        fmtTime(f.first), fmtTime(f.last), f.detail, f.rule.remediation, f.samples[0] || ""].map(csvCell).join(",");
    }));
    download("logsleuth-findings-" + stamp() + ".csv", "text/csv;charset=utf-8", "﻿" + lines.join("\r\n"));
  });

  $("expJson").addEventListener("click", function () {
    if (!needResults()) return;
    var r = state.results;
    var slim = function (rule) { return { id: rule.id, name: rule.name, severity: rule.severity, owasp: rule.owasp, mitre: rule.mitre, cwe: rule.cwe, phase: rule.phase, remediation: rule.remediation }; };
    var out = {
      tool: "LogSleuth", generated: new Date().toISOString(), source: state.source || "pasted text",
      summary: r.summary,
      attackers: r.attackers,
      findings: r.findings.map(function (f) { return { rule: slim(f.rule), ip: f.ip, count: f.count, first: fmtTime(f.first), last: fmtTime(f.last), detail: f.detail, samples: f.samples }; }),
      recommendations: r.recommendations.map(function (x) { return { rule: slim(x.rule), hits: x.count, sources: x.ipCount }; })
    };
    out.summary = Object.assign({}, r.summary, { firstTs: fmtTime(r.summary.firstTs), lastTs: fmtTime(r.summary.lastTs) });
    download("logsleuth-results-" + stamp() + ".json", "application/json", JSON.stringify(out, null, 2));
  });

  $("expHtml").addEventListener("click", function () {
    if (!needResults()) return;
    download("logsleuth-report-" + stamp() + ".html", "text/html;charset=utf-8", buildReport(state.results));
  });

  function buildReport(r) {
    var s = r.summary;
    var css = "body{font:14px/1.5 Segoe UI,system-ui,sans-serif;color:#1b1f27;max-width:1000px;margin:30px auto;padding:0 16px}" +
      "h1{margin:0}h2{margin-top:28px;border-bottom:2px solid #2456d6;padding-bottom:4px}table{border-collapse:collapse;width:100%;font-size:13px}" +
      "th,td{border:1px solid #d9dde5;padding:6px 8px;text-align:left;vertical-align:top}th{background:#eef0f4}" +
      ".b{display:inline-block;padding:1px 8px;border-radius:10px;color:#fff;font-size:11px;font-weight:700}" +
      ".Critical{background:#b3261e}.High{background:#d9480f}.Medium{background:#b7791f}.Low{background:#2b7a4b}.None{background:#9aa3b2}" +
      ".mono{font-family:Consolas,monospace;font-size:12px;word-break:break-all}.muted{color:#5d6675}";
    var b = function (sev) { return '<span class="b ' + esc(sev) + '">' + esc(sev) + "</span>"; };
    var h = [];
    h.push("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>LogSleuth Incident Report</title><style>" + css + "</style></head><body>");
    h.push("<h1>LogSleuth Incident Report</h1><p class=\"muted\">Generated " + esc(fmtTime(Date.now())) + " | Source: " + esc(state.source || "pasted text") + "</p>");
    h.push("<h2>1. Executive summary</h2><p>" + fmtNum(s.parsed) + " requests from " + fmtNum(s.uniqueIps) + " IP addresses were analysed, covering " +
      esc(fmtTime(s.firstTs)) + " to " + esc(fmtTime(s.lastTs)) + ". " + fmtNum(s.maliciousRequests) + " requests were flagged, producing " +
      fmtNum(s.findingCount) + " findings from " + fmtNum(s.attackerCount) + " suspicious sources. The highest source risk score is <b>" +
      s.overallRisk + "/100</b> " + b(s.overallLevel) + ".</p>");
    h.push("<p>Findings by severity: " + SEV_ORDER.map(function (x) { return x + " " + (r.bySeverity[x] || 0); }).join(", ") + ".</p>");
    h.push("<h2>2. Threat sources</h2>");
    if (r.attackers.length) {
      h.push("<table><tr><th>IP</th><th>Risk</th><th>Requests</th><th>Flagged</th><th>Kill-chain stages</th><th>Active (UTC)</th></tr>");
      r.attackers.forEach(function (a) {
        h.push("<tr><td class=\"mono\">" + esc(a.ip) + "</td><td>" + a.score + " " + b(a.level) + "</td><td>" + fmtNum(a.requests) + "</td><td>" + fmtNum(a.malicious) +
          "</td><td>" + esc(a.phases.join(" > ")) + "</td><td>" + esc(fmtTime(a.first)) + "<br>" + esc(fmtTime(a.last)) + "</td></tr>");
      });
      h.push("</table>");
    } else h.push("<p>No suspicious sources found.</p>");
    h.push("<h2>3. Findings</h2>");
    if (r.findings.length) {
      h.push("<table><tr><th>Severity</th><th>Attack type</th><th>IP</th><th>Hits</th><th>Mapping</th><th>Evidence</th></tr>");
      r.findings.forEach(function (f) {
        h.push("<tr><td>" + b(f.rule.severity) + "</td><td>" + esc(f.rule.name) + (f.detail ? "<br><span class=\"muted\">" + esc(f.detail) + "</span>" : "") +
          "</td><td class=\"mono\">" + esc(f.ip) + "</td><td>" + fmtNum(f.count) + "</td><td>" + esc(f.rule.owasp) + "<br>" + esc(f.rule.mitre) + "<br>" + esc(f.rule.cwe) +
          "</td><td class=\"mono\">" + esc(f.samples[0] || "") + "</td></tr>");
      });
      h.push("</table>");
    } else h.push("<p>No findings.</p>");
    h.push("<h2>4. Recommendations</h2><ol>");
    r.recommendations.forEach(function (x) {
      h.push("<li><b>" + esc(x.rule.name) + "</b> " + b(x.rule.severity) + "<br>" + esc(x.rule.remediation) + "</li>");
    });
    h.push("</ol>");
    h.push("<p class=\"muted\">Produced by LogSleuth, a passive log-analysis tool. For use only on systems you own or are authorised to assess.</p></body></html>");
    return h.join("");
  }

  // Expose a small hook for automated testing.
  window.LogSleuthApp = { state: state, buildReport: buildReport };
})();
