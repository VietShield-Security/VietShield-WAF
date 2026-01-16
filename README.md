# VietShield WAF - WordPress Security Plugin

**Version:** 1.0.0  
**Web:** [https://vietshield.org](https://vietshield.org)  
**Requires PHP:** 7.4+  
**Requires WP:** 5.0+

VietShield WAF is a high-performance, lightweight Web Application Firewall designed specifically for WordPress. It provides robust protection against common web attacks while maintaining your site's speed and reliability.

## 🚀 Key Features

*   **Advanced WAF Engine**: Protects against SQL Injection (SQLi), Cross-Site Scripting (XSS), Remote Code Execution (RCE), Local File Inclusion (LFI), and Bad Bots.
*   **Live Traffic Monitoring**: Watch real-time traffic requests with detailed metadata (Country, ASN, User Agent).
*   **Intelligent IP Management**: Whitelist, Blacklist, and Temporary automatic blocking for suspicious IPs.
*   **Malware & File Scanner**: Detects core file modifications and potential malware injections.
*   **Login Security**: Protects against brute-force attacks and unauthorized login attempts.
*   **Geo-Blocking**: Block traffic from specific high-risk countries.
*   **Performance First**: Optimized architecture with early-blocking capabilities to minimize server load.

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

1.  Upload the `vietshield-waf` folder to the `/wp-content/plugins/` directory.
2.  Activate the plugin through the 'Plugins' menu in WordPress.
3.  Follow the **Setup Wizard** to configure basic protection settings.
4.  Navigate to **VietShield WAF > Settings** to fine-tune your security rules.

---

## ❓ FAQ

**Q: Will this slow down my site?**  
A: No. VietShield is optimized for performance. It uses intelligent bypass for static files and executes heavy logging tasks in the background.

**Q: I blocked myself! What do I do?**  
A: You can manually remove your IP from the `vietshield_ip_lists` database table, or rename the plugin folder via FTP to temporarily disable it.

---

**VietShield WAF** - Protected by Vietnam's Leading Security Experts.
