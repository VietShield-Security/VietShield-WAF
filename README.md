# VietShield WAF - WordPress Security Plugin

**Version:** 1.0.0  
**Web:** [https://vietshield.org](https://vietshield.org)  
**Requires PHP:** 7.4+ (Optimal: 8.4+)  
**Requires WP:** 5.0+ (Optimal: 6.9+)  
**Recommended Webserver:** Nginx/Openresty

VietShield WAF is a high-performance, lightweight Web Application Firewall designed specifically for WordPress. It provides robust protection against common web attacks while maintaining your site's speed and reliability.

## �️ Comprehensive Feature List

### 1. Advanced Web Application Firewall (WAF)
*   **Protection Engine**:
    *   **SQL Injection (SQLi)**: Blocks UNION SELECT, time-based, and error-based attacks.
    *   **Cross-Site Scripting (XSS)**: Prevents script injection and malicious event handlers.
    *   **Remote Code Execution (RCE)**: Stops shell command execution and PHP code injection.
    *   **Local File Inclusion (LFI)**: Blocks path traversal attempts (e.g., accessing `/etc/passwd`).
    *   **Advanced Injection**: Specialized rules for OGNL injection, protocol smuggling, and more.
*   **Firewall Modes**:
    *   **Learning Mode**: Logs threats silently without blocking (safe for testing).
    *   **Protecting Mode**: Actively blocks threats with instant feedback (Recommended).
*   **Early Blocking**: Intercepts threats at the web server level (supports `.htaccess` for Apache and `.user.ini` for Nginx/PHP-FPM) for maximum performance.
*   **Bad Bots & Scanners**: Automatically identifies and blocks automated tools like SQLMap, Nikto, Nuclei, and dubious User-Agents.
*   **XML-RPC Protection**: Options to limit or completely block XML-RPC requests to prevent amplification attacks.

### 2. Threat Intelligence & Validation
*   **Community Threat Feed**: Automatically syncs valid threat data from the VietShield Network (1-day, 7-day, or 30-day categories).
*   **Threat Sharing**: Contribute to the community by automatically sharing anonymized attack data (optional).
*   **Geo-Blocking**: Block traffic from specific high-risk countries or regions.
*   **Auto-Whitelist**:
    *   **Googlebot**: Automatically validates and whitelists real Google crawlers (updates daily).
    *   **Cloudflare**: Built-in support for Cloudflare's IP ranges to prevent false positives.
    *   **Admin Whitelist**: Automatically bypasses WAF checks for logged-in Administrators.

### 3. Malware & Integrity Scanner
*   **WP Core Scanner**: Verifies WordPress system files against the official repository to detect unauthorized modifications.
*   **Malware Scanner**:
    *   **Heuristic Analysis**: Detects obfuscated code, high-entropy strings, and hidden PHP shells.
    *   **Signature Matching**: Checks against a database of known malware patterns.
    *   **Dangerous Functions**: Flags potential backdoors using functions like `eval`, `base64_decode`, `shell_exec`, etc.
*   **Scheduled Scans**: Run scans Daily, Weekly, or Manually on Themes, Plugins, or Uploads.

### 4. Login Security
*   **Brute Force Protection**: Limits failed login attempts per IP.
*   **Smart Lockout**: Temporarily bans IPs after X failed attempts (duration configurable from 5m to 24h).
*   **Honeypot**: Invisible fields to trap bots submitting login forms.
*   **Email Notifications**: Receive alerts when someone is repeatedly failing to login.
*   **Author Enumeration**: Blocks attempts to fish for usernames via `?author=N` scans.

### 5. Live Traffic & Analytics
*   **Real-time Monitoring**: Watch requests hitting your site live with zero latency.
*   **Detailed Metadata**:
    *   **IP Analysis**: Country, City, ASN (ISP), and User-Agent.
    *   **Attack Details**: See exactly why a request was blocked (Rule ID, Payload).
*   **Privacy Focused**: Options to toggle "Log All Traffic" or "Log Blocked Only", with configurable retention periods.
*   **Performance**: Logging happens asynchronously to ensure it never slows down page loads.

### 6. IP Management
*   **Manual Control**: Easily Add/Remove IPs from Whitelist and Blacklist.
*   **Auto-Ban Logic**: Automatically moves IPs to a temporary ban list if they exceed rate limits or trigger high-severity rules.
*   **Rate Limiting**:
    *   **Global**: Limit total requests per minute per IP.
    *   **Login Page**: Stricter limits for login endpoints.
    *   **XML-RPC**: Specific limits for XML-RPC calls.

---

## 🏗️ Architecture & Operation Model

VietShield WAF intercepts requests early in the WordPress loading process to filter malicious traffic before it reaches your site's core functions.

```mermaid
graph TD
    User([User / Attacker]) -->|Request| WebServer
    WebServer -->|Processing| Plugin[VietShield WAF]
    
    subgraph "VietShield WAF Engine"
        Plugin -->|1. Check| IPCheck{IP Whitelist/Blacklist}
        IPCheck -- Blacklisted --> BlockAction[Block Request]
        IPCheck -- Whitelisted --> AllowAction[Allow Request]
        IPCheck -- Unknown --> StaticCheck{Static File?}
        
        StaticCheck -- Yes --> AllowAction
        StaticCheck -- No --> WAFAnalysis
        
        WAFAnalysis[Request Analysis] -->|Inspect| Payload{Signatures Detected?}
        payload -->|SQLi/XSS/RCE| BlockAction
        payload -->|Clean| RateLimit{Rate Limit Check}
        
        RateLimit -- Exceeded --> BlockAction
        RateLimit -- OK --> Logger[Traffic Logger]
    end
    
    AllowAction --> Logger
    BlockAction -->|403 Forbidden| User
    Logger -->|Pass| WordPress[WordPress Core]
    WordPress -->|Response| User
```

1.  **Early Interception**: The WAF initializes before most WordPress plugins to catch threats early.
2.  **IP Filtering**: Checks headers against local databases of trusted and banned IPs.
3.  **Static Bypass**: Automatically skips analysis for static assets (images, css, js) to ensure strictly zero latency for assets.
4.  **Deep Analysis**: Scans GET, POST, and COOKIE data against a comprehensive rule set.
5.  **Logging**: Records traffic details and metadata asynchronously to prevent performance bottlenecks.

---

## 📖 Usage Guide

### 1. Dashboard
The main dashboard gives you a helicopter view of your site's security status.
*   **Statistics**: View total requests, blocked attacks, and threat summaries for the last 7 or 30 days.
*   **Quick Actions**: Quickly enable/disable major protection modules.

### 2. Live Traffic
Monitor who is visiting your site in real-time.
*   **View Logs**: See IP, Request URI, Method, Response Code, Country, and ASN.
*   **Analyze Attacks**: Blocked requests highlight the specific rule triggered (e.g., `sqli`, `bad_bot`).
*   **Action**: Click "Block" on any log entry to instantly ban that IP.

### 3. Firewall (IP Manager)
Manage access control lists.
*   **Whitelist**: Add trusted IPs (e.g., your office IP, payment gateways) to bypass all WAF checks.
*   **Blacklist**: Permanently block known malicious IPs.
*   **Temporary Blocks**: View IPs automatically banned by rate limiting or brute-force protection. They will be released after the configured duration.

### 4. File & Malware Scanners
Ensure your site's integrity.
*   **File Scanner**: Compares your WordPress core files against the official repository checksums to detect unauthorized modifications.
*   **Malware Scanner**: Scans themes and plugins for suspicious code patterns (php shells, obfuscated code).
*   **Schedule**: Configure scans to run daily or weekly in the background.

### 5. Settings
Customize the WAF behavior.
*   **Firewall Mode**: 
    *   *Learning*: Logs attacks but does not block them (good for testing).
    *   *Protecting*: Actively blocks threats (Recommended).
*   **Rate Limiting**: Set thresholds for requests per minute to stop DoS attacks.
*   **Country Blocking**: Select countries to block entirely.

---

## 🔧 Installation

1.  Download the latest release ZIP file from the [Releases page](https://github.com/VietShield-Security/VietShield-WAF/releases).
2.  Go to your WordPress Admin Dashboard > **Plugins** > **Add New** > **Upload Plugin**.
3.  Upload the `vietshield-waf.zip` file and click **Install Now**.
4.  **Activate** the plugin.
5.  Follow the **Setup Wizard** to configure basic protection settings.
6.  Go to **VietShield WAF > Settings** to fine-tune your configuration and enjoy the protection!

---

## ❓ FAQ

**Q: Will this slow down my site?**  
A: No. VietShield is optimized for performance. It uses intelligent bypass for static files and executes heavy logging tasks in the background.

**Q: I blocked myself! What do I do?**  
A: You can manually remove your IP from the `vietshield_ip_lists` database table, or rename the plugin folder via FTP to temporarily disable it.

---

**VietShield WAF** - Protected by Vietnam's Leading Security Experts.
