=== VietShield WAF ===
Contributors: vietshield
Tags: security, firewall, waf, malware, protection
Requires at least: 5.0
Tested up to: 6.7
Stable tag: 1.0.3
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

High-performance Web Application Firewall for WordPress with real-time threat detection, advanced traffic analysis, and malware scanning.

== Description ==

VietShield WAF intercepts requests early in the WordPress loading process to filter malicious traffic before it reaches your site's core functions. It features a robust firewall engine, real-time traffic monitoring, and comprehensive threat intelligence integration.

**Key Features:**

*   **Proactive Firewall:** Blocks SQL Injection (SQLi), Cross-Site Scripting (XSS), Remote Code Execution (RCE), LFI, and other OWASP Top 10 threats.
*   **Zero-Latency Static Bypass:** Automatically skips analysis for static assets (images, CSS, JS) to maintain site speed.
*   **Real-time Traffic Logger:** detailed insights into who is visiting your site, including IP country and attack payloads.
*   **IP Management:** Manual whitelist, blacklist, and temporary blocking capabilities.
*   **Geo-Blocking:** Block traffic from high-risk countries.
*   **Malware Scanner:** Integrated file integrity monitoring and malware detection for themes and plugins.
*   **Login Security:** Protects against brute-force attacks and author enumeration.

**Contact:** hello@vietshield.org

== External Services ==

This plugin relies on the following third-party services to provide enhanced security features. All external connections are documented below:

1.  **VietShield Intelligence Network**
    *   **Service:** Threat Intelligence Feed
    *   **Why we use it:** To synchronize the latest list of known malicious IPs (e.g., spammers, botnets) for preemptive blocking.
    *   **Data Sent:** Your server's IP address (standard HTTP request) and API authentication headers. No personal user data is sent.
    *   **Link:** [VietShield Intelligence](https://intelligence.vietshield.org)
    *   **Terms & Privacy:** [Privacy Policy](https://vietshield.org/privacy)

2.  **Google**
    *   **Service:** Googlebot IP Ranges
    *   **Why we use it:** To fetch the official list of Googlebot IP addresses for whitelisting, preventing accidental blocking of search crawlers.
    *   **Data Sent:** None (Public JSON feed fetch).
    *   **Link:** [Google Search Central](https://developers.google.com/search/apis/ipranges/googlebot.json)
    *   **Terms & Privacy:** [Google Privacy Policy](https://policies.google.com/privacy)

3.  **Cloudflare**
    *   **Service:** Cloudflare IP Ranges
    *   **Why we use it:** To fetch official Cloudflare IP ranges to trust headers from Cloudflare proxy servers.
    *   **Data Sent:** None (Public text/JSON feed fetch).
    *   **Link:** [Cloudflare IP Ranges](https://www.cloudflare.com/ips/)
    *   **Terms & Privacy:** [Cloudflare Privacy Policy](https://www.cloudflare.com/privacypolicy/)

== Installation ==

1.  Upload the `vietshield-waf` folder to the `/wp-content/plugins/` directory.
2.  Activate the plugin through the 'Plugins' menu in WordPress.
3.  Go to **VietShield WAF > Settings** to configure your protection preferences.
4.  Run the **Setup Wizard** for specific environment configurations.

== Frequently Asked Questions ==

= Will this slow down my site? =
No. VietShield is optimized for performance. It uses intelligent bypass for static files and executes heavy logging tasks to prevent bottlenecks.

= I blocked myself! What do I do? =
You can manually remove your IP from the `vietshield_ip_lists` database table using phpMyAdmin, or rename the plugin folder via FTP to temporarily disable it.

== Screenshots ==

1.  **Dashboard overview**
2.  **Firewall settings**
3.  **Live traffic logs**

== Changelog ==

= 1.0.3 =
*   Fixed: Wizard setup 403 Forbidden error at step 3 when completing setup.
*   Fixed: Nonce verification mismatch in wizard AJAX handlers.
*   Improved: Wizard "Complete Setup" button now works correctly.

= 1.0.2 =
*   Initial release to WordPress.org directory.
*   Added comprehensive WAF engine.
*   Integrated Threat Intelligence sharing.
