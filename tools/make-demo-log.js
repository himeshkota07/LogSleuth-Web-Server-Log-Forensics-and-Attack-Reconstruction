// Generates samples/demo_access.log: a day of ordinary shop traffic with a few behaviour-based incidents
// (content brute-forcing, a login brute force that ends in success, and a bulk download) to demo the dashboard.
// Run with:  node tools/make-demo-log.js
"use strict";
var fs = require("fs"), path = require("path");

var seed = 42;
function rand() { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; }
function pick(a) { return a[Math.floor(rand() * a.length)]; }

function line(ip, sec, method, url, status, bytes, ua, ref) {
  var h = 9 + Math.floor(sec / 3600), m = Math.floor(sec % 3600 / 60), s = sec % 60;
  var p = function (n) { return (n < 10 ? "0" : "") + n; };
  return ip + " - - [14/Sep/2026:" + p(h) + ":" + p(m) + ":" + p(s) + ' +0530] "' + method + " " + url + ' HTTP/1.1" ' +
    status + " " + bytes + ' "' + (ref || "-") + '" "' + ua + '"';
}

var BROWSERS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Mobile Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"
];
var PAGES = ["/", "/products?id=", "/products?id=", "/category/shoes", "/category/bags", "/cart", "/search?q=sneakers",
  "/search?q=leather+bag", "/about-us", "/contact", "/static/app.js", "/static/style.css", "/images/banner.jpg"];

var out = [];
// Normal customers across 8 hours.
for (var i = 0; i < 6000; i++) {
  var sec = Math.floor(rand() * 8 * 3600);
  var ip = "198.51.100." + (1 + Math.floor(rand() * 180));
  var pg = pick(PAGES);
  if (pg === "/products?id=") pg += 1 + Math.floor(rand() * 120);
  var status = rand() < 0.02 ? 404 : 200;
  out.push({ t: sec, l: line(ip, sec, "GET", pg, status, 800 + Math.floor(rand() * 40000), pick(BROWSERS), "https://shop.example/") });
}
// Customers logging in normally (occasional typo).
for (var c = 0; c < 80; c++) {
  var cs = Math.floor(rand() * 8 * 3600), cip = "198.51.100." + (1 + Math.floor(rand() * 180)), ua = pick(BROWSERS);
  if (rand() < 0.2) out.push({ t: cs, l: line(cip, cs, "POST", "/login", 401, 310, ua) });
  out.push({ t: cs + 4, l: line(cip, cs + 4, "POST", "/login", 302, 290, ua) });
}

// Incident 1 (11:02): automated content discovery from 203.0.113.45, finds an exposed config file.
var base = 2 * 3600 + 120;
for (var d = 0; d < 60; d++) out.push({ t: base + Math.floor(d / 2), l: line("203.0.113.45", base + Math.floor(d / 2), "GET", "/" + pick(["old", "test", "dev", "tmp", "bak", "v1", "beta"]) + d, 404, 196, "gobuster/3.6") });
out.push({ t: base + 35, l: line("203.0.113.45", base + 35, "GET", "/.env", 200, 612, "gobuster/3.6") });
out.push({ t: base + 36, l: line("203.0.113.45", base + 36, "GET", "/admin/", 302, 0, "gobuster/3.6") });

// Incident 2 (13:15): password guessing against /login from 192.0.2.77, then a successful login and bulk export.
base = 4 * 3600 + 900;
for (var k = 0; k < 40; k++) out.push({ t: base + k * 4, l: line("192.0.2.77", base + k * 4, "POST", "/login", 401, 310, "python-requests/2.32") });
out.push({ t: base + 170, l: line("192.0.2.77", base + 170, "POST", "/login", 302, 290, "python-requests/2.32") });
out.push({ t: base + 180, l: line("192.0.2.77", base + 180, "GET", "/admin/customers", 200, 48210, "python-requests/2.32") });
out.push({ t: base + 190, l: line("192.0.2.77", base + 190, "GET", "/admin/customers/export?format=csv", 200, 7340032, "python-requests/2.32") });

// Incident 3 (15:40): a single noisy crawler hammering the catalogue.
base = 6 * 3600 + 2400;
for (var r = 0; r < 200; r++) out.push({ t: base + Math.floor(r / 5), l: line("203.0.113.99", base + Math.floor(r / 5), "GET", "/products?id=" + r, 200, 2100, "Go-http-client/1.1") });

out.sort(function (a, b) { return a.t - b.t; });
var dir = path.join(__dirname, "..", "samples");
fs.mkdirSync(dir, { recursive: true });
fs.writeFileSync(path.join(dir, "demo_access.log"), out.map(function (o) { return o.l; }).join("\n") + "\n");
console.log("Wrote " + out.length + " lines to samples/demo_access.log");
