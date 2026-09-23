/*
 * LogSleuth - Detection rule catalogue
 * Each rule is mapped to OWASP Top 10 (2021), MITRE ATT&CK, CWE and a Cyber Kill Chain phase,
 * and carries a remediation so every finding ends in a defensive recommendation.
 */
(function (root) {
  "use strict";

  var SEVERITY_WEIGHT = { Critical: 40, High: 20, Medium: 8, Low: 3, Info: 1 };

  var KILL_CHAIN = [
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command & Control",
    "Actions on Objectives"
  ];

  // Signature rules: evaluated against every single request.
  // `test` receives the parsed entry (with decoded fields) and returns true on a match.
  var SIGNATURE_RULES = [
    {
      id: "SQLI",
      name: "SQL Injection attempt",
      severity: "High",
      owasp: "A03:2021 - Injection",
      mitre: "T1190 - Exploit Public-Facing Application",
      cwe: "CWE-89",
      phase: "Exploitation",
      pattern: /(\bunion\b[\s\S]{0,40}\bselect\b)|(\bor\b\s*['"]?\d+['"]?\s*=\s*['"]?\d+)|('\s*or\s*'[^']*'\s*=\s*')|(\bsleep\s*\(\s*\d+\s*\))|(\bbenchmark\s*\()|(\binformation_schema\b)|(\bwaitfor\s+delay\b)|(\bextractvalue\s*\()|(\bload_file\s*\()|(--\s*$)|(;\s*drop\s+table)/i,
      fields: ["url"],
      remediation: "Use parameterised queries / prepared statements or an ORM for every database call; validate input types (e.g. id must be an integer); run the DB account with least privilege; deploy a WAF rule set such as OWASP CRS."
    },
    {
      id: "XSS",
      name: "Cross-Site Scripting (XSS) attempt",
      severity: "Medium",
      owasp: "A03:2021 - Injection",
      mitre: "T1189 - Drive-by Compromise",
      cwe: "CWE-79",
      phase: "Delivery",
      pattern: /(<\s*script\b)|(javascript\s*:)|(\bon(error|load|mouseover|focus|click)\s*=)|(<\s*(img|svg|iframe|body)\b[^>]*>)|(document\.cookie)|(\balert\s*\()/i,
      fields: ["url", "referer"],
      remediation: "Apply context-aware output encoding for all user-supplied data; enable a strict Content-Security-Policy; set cookies HttpOnly and SameSite; sanitise rich-text input with a vetted library."
    },
    {
      id: "TRAVERSAL",
      name: "Path Traversal / Local File Inclusion",
      severity: "High",
      owasp: "A01:2021 - Broken Access Control",
      mitre: "T1083 - File and Directory Discovery",
      cwe: "CWE-22",
      phase: "Exploitation",
      pattern: /(\.\.\/|\.\.\\)|(\/etc\/(passwd|shadow|hosts))|(c:\\windows\\win\.ini)|(php:\/\/(filter|input))|(\bfile:\/\/)/i,
      fields: ["url"],
      remediation: "Never build file paths from user input; map requested resources to an allow-list of identifiers; canonicalise paths and verify they stay inside the web root; disable allow_url_include."
    },
    {
      id: "CMDI",
      name: "OS Command Injection / Web-shell command",
      severity: "Critical",
      owasp: "A03:2021 - Injection",
      mitre: "T1059 - Command and Scripting Interpreter",
      cwe: "CWE-78",
      phase: "Command & Control",
      pattern: /([?&](cmd|exec|command)=)|([;|`]\s*(whoami|id|uname|cat|ls|wget|curl|nc|bash|sh)\b)|(\$\((whoami|id|uname)\))/i,
      fields: ["url"],
      remediation: "Avoid shell calls with user input; use language APIs with argument arrays; remove any uploaded scripts; make upload directories non-executable; isolate the host and rotate credentials if a web shell is confirmed."
    },
    {
      id: "LOG4SHELL",
      name: "JNDI / Log4Shell exploit probe",
      severity: "Critical",
      owasp: "A06:2021 - Vulnerable and Outdated Components",
      mitre: "T1190 - Exploit Public-Facing Application",
      cwe: "CWE-917",
      phase: "Exploitation",
      pattern: /\$\{\s*(jndi|\$\{lower:j\}|env|sys)[^}]*[:}]/i,
      fields: ["url", "ua", "referer"],
      remediation: "Maintain a software bill of materials; upgrade Log4j to 2.17.1+ (or remove JndiLookup); block outbound LDAP/RMI from servers; patch components on a defined SLA."
    },
    {
      id: "SCANNER",
      name: "Automated vulnerability scanner / recon tool",
      severity: "Medium",
      owasp: "A05:2021 - Security Misconfiguration",
      mitre: "T1595 - Active Scanning",
      cwe: "CWE-200",
      phase: "Reconnaissance",
      pattern: /(nikto|sqlmap|nmap|masscan|zgrab|dirbuster|dirb|gobuster|wpscan|acunetix|nessus|openvas|nuclei|ffuf|wfuzz|hydra|burp|python-requests|go-http-client|curl\/)/i,
      fields: ["ua"],
      remediation: "Rate-limit and block known scanner fingerprints at the WAF/reverse proxy; minimise information disclosed in banners and error pages; run your own authorised scans first so findings are fixed before attackers find them."
    },
    {
      id: "SENSITIVE",
      name: "Access to sensitive file or directory",
      severity: "High",
      owasp: "A05:2021 - Security Misconfiguration",
      mitre: "T1552.001 - Credentials In Files",
      cwe: "CWE-538",
      phase: "Reconnaissance",
      pattern: /(\/\.env\b)|(\/\.git\/)|(\/\.svn\/)|(\/\.htpasswd)|(\/wp-config\.php)|(\/config\.(php|bak|old|inc))|(\.(sql|bak|old|swp|tar\.gz|zip)(\?|$))|(\/backup\/)|(\/phpinfo\.php)|(\/server-status)|(\/web\.config)/i,
      fields: ["path"],
      remediation: "Keep secrets, backups and VCS folders outside the web root; deny dot-files in the web server config; store secrets in a vault/environment manager; rotate any credential that was ever web-accessible."
    },
    {
      id: "ADMIN",
      name: "Admin / management interface access",
      severity: "Low",
      owasp: "A01:2021 - Broken Access Control",
      mitre: "T1078 - Valid Accounts",
      cwe: "CWE-284",
      phase: "Reconnaissance",
      pattern: /^\/(admin|administrator|wp-admin|phpmyadmin|manager\/html|cpanel|dashboard\/admin)(\/|$|\?)/i,
      fields: ["path"],
      remediation: "Expose admin panels only via VPN / IP allow-list; enforce MFA for privileged accounts; log and alert on every privileged action."
    },
    {
      id: "UPLOAD_EXEC",
      name: "Executable script requested from upload directory",
      severity: "Critical",
      owasp: "A08:2021 - Software and Data Integrity Failures",
      mitre: "T1505.003 - Web Shell",
      cwe: "CWE-434",
      phase: "Installation",
      pattern: /\/(uploads?|images|media|files|tmp)\/[^?]*\.(php\d?|phtml|jsp|aspx?|cgi|pl|py|sh)(\?|$)/i,
      fields: ["path"],
      remediation: "Validate uploads by content (magic bytes) not extension; rename files to random names; store uploads outside the web root or on object storage; configure the server to never execute scripts in upload folders."
    },
    {
      id: "BAD_METHOD",
      name: "Unusual / dangerous HTTP method",
      severity: "Low",
      owasp: "A05:2021 - Security Misconfiguration",
      mitre: "T1595.002 - Vulnerability Scanning",
      cwe: "CWE-650",
      phase: "Reconnaissance",
      test: function (e) { return /^(PUT|DELETE|TRACE|TRACK|CONNECT|PROPFIND|DEBUG)$/i.test(e.method); },
      remediation: "Allow only the HTTP methods the application needs (typically GET, POST, HEAD); disable TRACE/TRACK and WebDAV."
    }
  ];

  // Behavioural rules: evaluated on the sliding history of a single source IP.
  var BEHAVIOUR_RULES = [
    {
      id: "DIR_BRUTE",
      name: "Directory / content brute-forcing",
      severity: "Medium",
      owasp: "A05:2021 - Security Misconfiguration",
      mitre: "T1595.003 - Wordlist Scanning",
      cwe: "CWE-200",
      phase: "Reconnaissance",
      threshold: "20 or more HTTP 404 responses within 60 seconds",
      remediation: "Throttle clients producing bursts of 404s (fail2ban / WAF rate-limit); return uniform error pages; do not leave unlinked content on the server."
    },
    {
      id: "LOGIN_BRUTE",
      name: "Login brute-force / credential stuffing",
      severity: "High",
      owasp: "A07:2021 - Identification and Authentication Failures",
      mitre: "T1110 - Brute Force",
      cwe: "CWE-307",
      phase: "Delivery",
      threshold: "10 or more failed logins within 5 minutes",
      remediation: "Enforce account lockout / progressive delays and CAPTCHA; require MFA; check passwords against breached-password lists; alert on authentication failure spikes."
    },
    {
      id: "ACCOUNT_TAKEOVER",
      name: "Successful login after repeated failures (probable account takeover)",
      severity: "Critical",
      owasp: "A07:2021 - Identification and Authentication Failures",
      mitre: "T1078 - Valid Accounts",
      cwe: "CWE-307",
      phase: "Exploitation",
      threshold: "a successful login preceded by 5 or more failures from the same IP",
      remediation: "Force a password reset and revoke sessions for the affected account; enable MFA; review all actions taken by the account after the login."
    },
    {
      id: "RATE",
      name: "Abnormal request rate (automation / DoS)",
      severity: "Medium",
      owasp: "A04:2021 - Insecure Design",
      mitre: "T1498 - Network Denial of Service",
      cwe: "CWE-770",
      phase: "Reconnaissance",
      threshold: "more than 120 requests within 60 seconds",
      remediation: "Apply per-IP and per-session rate limits at the edge (CDN / reverse proxy); use bot management; autoscale behind a load balancer."
    },
    {
      id: "EXFIL",
      name: "Large data transfer (possible exfiltration)",
      severity: "Critical",
      owasp: "A01:2021 - Broken Access Control",
      mitre: "T1041 - Exfiltration Over C2 Channel",
      cwe: "CWE-200",
      phase: "Actions on Objectives",
      threshold: "a single successful response larger than 1 MB, or more than 5 MB served to one IP",
      remediation: "Apply data-loss-prevention limits on bulk exports; paginate APIs; alert on unusual egress volume; encrypt backups and never store them in the web root."
    }
  ];

  var api = {
    SEVERITY_WEIGHT: SEVERITY_WEIGHT,
    KILL_CHAIN: KILL_CHAIN,
    SIGNATURE_RULES: SIGNATURE_RULES,
    BEHAVIOUR_RULES: BEHAVIOUR_RULES,
    ruleById: function (id) {
      var all = SIGNATURE_RULES.concat(BEHAVIOUR_RULES);
      for (var i = 0; i < all.length; i++) if (all[i].id === id) return all[i];
      return null;
    }
  };

  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.LSRules = api;
})(this);
