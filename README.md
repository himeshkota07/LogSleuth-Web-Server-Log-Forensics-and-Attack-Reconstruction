# LogSleuth: Web Server Log Forensics & Attack Reconstruction

Ethical Hacking mini project (23AML17344), B.N.M. Institute of Technology.

LogSleuth analyses a web server's access log from the **defender's side**. It finds signs of reconnaissance, injection attempts,
brute-force logins, account takeover and data exfiltration. It groups them per attacker, maps each finding to the
**OWASP Top 10 (2021)**, **MITRE ATT&CK**, **CWE** and the **Cyber Kill Chain**, gives each source a risk score, and
recommends a fix for each weakness it finds.

**Live demo:** https://logsleuth-nine.vercel.app/
(demo log: https://logsleuth-nine.vercel.app/samples/demo_access.log)

## How to run (nothing to install)

1. Open the [live demo](https://logsleuth-nine.vercel.app/), or double-click `index.html` to run it offline in Edge or Chrome.
2. Drop `samples/demo_access.log` onto the page, or paste your own Apache/Nginx log lines.
3. Click **Analyse log** for the full dashboard, or **Live replay** to watch alerts appear as the log streams in.
4. Click an attacker row to filter findings, and click a finding to see the evidence lines and the fix.
5. Export the results as an HTML report, CSV or JSON.

## Project structure

| Path | Purpose |
|---|---|
| `index.html`, `css/style.css`, `favicon.svg` | Dashboard page (light/dark theme, works on mobile) |
| `js/rules.js` | 15 detection rules with severity, OWASP, MITRE ATT&CK, CWE, kill-chain phase and remediation |
| `js/engine.js` | Log parser, signature and behavioural detection, per-IP risk scoring, timeline and recommendations |
| `js/app.js` | User interface: file/paste input, batch analysis, live replay, charts, filters, export |
| `samples/demo_access.log` | Demo log: ordinary shop traffic plus 3 incidents |
| `tools/make-demo-log.js` | Regenerates the demo log (`node tools/make-demo-log.js`) |
| `test/engine.test.js` | 20 unit tests for the engine (`node test/engine.test.js`) |
| `test/ui.test.js` | 15 end-to-end tests in headless Edge/Chrome (`node test/ui.test.js`) |
| `vercel.json` | Vercel hosting config: security headers and clean URLs |
| `.vercelignore` | Keeps `test/` and `tools/` off the live site |

The tests use Node.js and the Edge/Chrome already on the machine. The page itself needs only a browser.
To run the browser tests against the deployed site instead of the local file:

```
LS_URL=https://logsleuth-nine.vercel.app/ node test/ui.test.js
```

## Detection approach

- **Signature rules** (per request, after decoding the URL up to 3 times): SQL injection, XSS, path traversal,
  command injection / web shell, JNDI (Log4Shell), scanner user-agents, sensitive files (`.env`, `.git`, backups),
  admin panels, scripts in upload folders, and unusual HTTP methods.
- **Behavioural rules** (per source IP, sliding windows):
  - Directory brute force: 20 or more 404s in 60 s.
  - Login brute force: 10 or more failed logins in 5 min.
  - Account takeover: a successful login after 5 or more failures.
  - Request flooding: more than 120 requests in 60 s.
  - Exfiltration: a single response over 1 MB, or more than 5 MB served to one IP in total.
- **Risk score (0-100)**: the severity weight of each distinct attack type (Critical 40, High 20, Medium 8, Low 3),
  plus a small bonus for repeated hits and a bonus for how far along the kill chain the source got.

## Deployment

The site is a static app (no build step, no server) hosted on Vercel from the `main` branch of this repository.
Every push to `main` redeploys automatically.

`vercel.json` serves every page with these security headers:

| Header | Value / purpose |
|---|---|
| `Content-Security-Policy` | Only the site's own scripts can run; no plugins, framing or form submissions |
| `X-Frame-Options` | `DENY`: the site can't be embedded in another page (clickjacking protection) |
| `X-Content-Type-Options` | `nosniff`: files are only treated as the type the server declares |
| `Referrer-Policy` | `no-referrer`: the site's URL isn't sent to other sites |
| `Permissions-Policy` | Camera, microphone and location access are disabled |

To deploy your own copy: import the repository at vercel.com with **Framework Preset: Other**, and leave the
build command and output directory empty.

## Ethics and legal use

LogSleuth is passive. It only reads logs and never sends traffic anywhere. Use it only on logs from systems you own or
are authorised to assess, and treat logs as personal data (they contain IP addresses) under the IT Act 2000 and the
DPDP Act 2023.

## Future scope

- Parse IIS, JSON and cloud load-balancer logs.
- Add GeoIP and threat-intelligence reputation lookups.
- Add ML anomaly detection alongside the rules.
- Auto-generate WAF or fail2ban block rules.
- Tail a live log over WebSocket.
- Send alerts to a SIEM.