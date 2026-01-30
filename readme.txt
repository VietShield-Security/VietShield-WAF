=== VietShield WAF ===
Contributors: vietshield
Tags: security, firewall, waf, malware, protection
Requires at least: 5.0
Tested up to: 6.9
Stable tag: 1.0.7
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

= 1.0.7 =
*   New: Googlebot Whitelist Card in Firewall page with Sync Now button and Show/Hide toggle
*   New: Redesigned Setup Wizard - Simplified 2-step flow (Choose Mode → Activate)
*   New: Professional progress bar animation during wizard activation
*   New: Settings page reorganization with improved card groupings
*   Fixed: whitelist_googlebot option not being saved in Settings
*   Fixed: Wizard AJAX action name mismatch causing wizard to hang at 100%
*   Fixed: "vietshieldWizard is not defined" JavaScript error in wizard
*   Fixed: Duplicate "Recommended" text in wizard mode selection
*   Fixed: Threat Intelligence not syncing after wizard completion
*   Fixed: Plugin Information icon size/alignment in About tab
*   Fixed: Learning Mode selection being lost when navigating to step 2 (now single-page flow)

= 1.0.6 =
*   Fixed: Translation warning `_load_textdomain_just_in_time` on block page
*   Fixed: CAPTCHA challenge not triggering for some attack types
*   Improved: Block page now displays specific attack message

= 1.0.5 =
*   New: Auto-Update from GitHub Releases - Plugin now supports automatic updates from GitHub.
*   New: Checks for new releases every 12 hours.
*   New: Shows update notification in WordPress admin.
*   New: "View Details" popup shows changelog from GitHub release.
*   New: One-click update directly from Plugins page.

= 1.0.4 =
*   New: CAPTCHA Challenge - Optional CAPTCHA verification instead of blocking for suspicious requests.
*   New: Supports Google reCAPTCHA v2/v3, Cloudflare Turnstile, and hCaptcha.
*   New: Country Blocking Mode - New "Allow Selected Countries Only" option.
*   Improved: RCE protection now defaults to OFF in setup wizard to prevent false positives.
*   Improved: Wizard z-index set to 9985 to prevent notification overlapping.
*   Improved: Standardized attack_type to 'threat_intelligence' across all code.

= 1.0.3 =
*   Fixed: Wizard setup 403 Forbidden error at step 3 when completing setup.
*   Fixed: Nonce verification mismatch in wizard AJAX handlers.
*   Fixed: RCE false positives with marketing/tracking parameters (e.g., typ=organic|||src=google|||id=(none)).
*   Fixed: Block page CSS styling issues for responsive design.
*   Fixed: country_block attack type being incorrectly synced to Threats Sharing API.
*   Improved: Wizard "Complete Setup" button now works correctly.
*   Improved: Enhanced RCE whitelist patterns to support ||| delimiter format used by marketing tracking.
*   Improved: Advanced injection detection patterns to avoid matching marketing parameters.
*   Improved: Increased default Global Rate Limit from 100 to 250 requests per minute.
*   Improved: Professional redesigned 403 block page with glassmorphism, animations, and accessibility.

= 1.0.2 =
*   Initial release to WordPress.org directory.
*   Added comprehensive WAF engine.
*   Integrated Threat Intelligence sharing.
