<?php
/**
 * WAF Engine - Core firewall processing
 * 
 * @package VietShield_WAF
 */

namespace VietShield\WAF;

if (!defined('ABSPATH')) {
    exit;
}

class WAFEngine {
    
    /**
     * Singleton instance
     */
    private static $instance = null;
    
    /**
     * Plugin options
     */
    private $options = [];
    
    /**
     * Request analyzer instance
     */
    private $request_analyzer = null;
    
    /**
     * Rule matcher instance
     */
    private $rule_matcher = null;
    
    /**
     * Threat detector instance
     */
    private $threat_detector = null;
    
    /**
     * Response handler instance
     */
    private $response_handler = null;
    
    /**
     * Traffic logger instance
     */
    private $logger = null;
    
    /**
     * Current request data
     */
    private $request_data = [];
    
    /**
     * Get singleton instance
     */
    public static function get_instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    /**
     * Private constructor
     */
    private function __construct() {
        $this->options = get_option('vietshield_options', []);
    }
    
    /**
     * Initialize WAF
     */
    public function init() {
        // Load dependencies
        $this->load_dependencies();
        
        // Initialize components
        $this->request_analyzer = new RequestAnalyzer();
        $this->rule_matcher = new RuleMatcher();
        $this->threat_detector = new ThreatDetector($this->rule_matcher);
        $this->response_handler = new ResponseHandler();
        $this->logger = new \VietShield\Logging\TrafficLogger();
        
        // Run WAF check
        $this->run();
    }
    
    /**
     * Load required files
     */
    private function load_dependencies() {
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/waf/class-request-analyzer.php';
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/waf/class-rule-matcher.php';
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/waf/class-threat-detector.php';
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/waf/class-response-handler.php';
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/logging/class-traffic-logger.php';
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-ip-manager.php';
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-rate-limiter.php';
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-geo-locator.php';
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-country-blocker.php';
    }
    
    /**
     * Run WAF checks
     */
    public function run() {
        // Skip for CLI
        if (php_sapi_name() === 'cli') {
            return;
        }
        
        // Check if WAF is enabled - if disabled, don't log and don't block anything
        $options = get_option('vietshield_options', []);
        if (empty($options['waf_enabled'])) {
            return; // WAF disabled - no logging, no blocking
        }
        
        // Get client IP
        $ip = $this->get_client_ip();
        
        // Check if this is an admin request EARLY (before analyzing)
        // Use raw server variables for faster and more reliable detection
        $is_admin = $this->is_admin_request_early();
        
        // Analyze request
        $this->request_data = $this->request_analyzer->analyze();
        $this->request_data['ip'] = $ip;
        
        // Double-check with analyzed data (more thorough)
        if (!$is_admin) {
            $is_admin = $this->is_admin_request();
        }
        
        // Skip static files EARLY - before incrementing
        $is_static = $this->is_static_file($this->request_data['uri'] ?? '');
        
        // Skip WordPress internal requests
        $should_skip = $this->should_skip_waf();
        
        // Final check: if still not admin, verify one more time with simple pattern
        // Sometimes early check might miss, so double-check here
        if (!$is_admin) {
            $uri_check = $this->request_data['uri'] ?? '';
            $original_uri = $_SERVER['REQUEST_URI'] ?? '';
            if (strpos($uri_check, '/wp-admin/') !== false || 
                strpos($original_uri, '/wp-admin/') !== false) {
                $is_admin = true;
            }
        }
        
        // Check usage counting
        // We want to count:
        // 1. Frontend requests (is_admin = false)
        // 2. Admin area requests when NOT logged in (e.g. login attacks)
        // We want to SKIP:
        // 1. Static files
        // 2. Internal WP requests (cron, heartbeat)
        // 3. Admin area requests when LOGGED IN (dashboard usage)
        
        $is_logged_in = $this->is_user_logged_in_early();
        $referer = $this->request_data['referer'] ?? $_SERVER['HTTP_REFERER'] ?? '';
        $is_admin_referer = (strpos($referer, '/wp-admin/') !== false);
        
        // Count request if it's NOT a static file, NOT internal skip
        // AND validation logic:
        // - If NOT logged in: Count everything (except skipped)
        // - If LOGGED IN: Count only if NOT Admin AND NOT referred by Admin (Frontend usage)
        if (!$is_static && !$should_skip && (!$is_logged_in || (!$is_admin && !$is_admin_referer))) {
            $this->logger->increment_total_requests();
        }
        
        // Check whitelist first
        $ip_manager = new \VietShield\Firewall\IPManager();
        if ($ip_manager->is_whitelisted($ip)) {
            $this->log_request('allowed', '', '', 'low');
            return;
        }
        
        // Check if admin and whitelist_admins is enabled
        if ($this->is_whitelisted_admin()) {
            return;
        }
        
        // Check blacklist
        if ($ip_manager->is_blacklisted($ip)) {
            $this->block_request('ip_blacklisted', 'IP is blacklisted', 'high');
            return;
        }
        
        // Check threat intelligence feed
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-threat-intelligence.php';
        if (\VietShield\Firewall\ThreatIntelligence::is_enabled()) {
            $threat_intel = new \VietShield\Firewall\ThreatIntelligence();
            if ($threat_intel->is_threat_ip($ip)) {
                $this->block_request('threat_intelligence', 'IP found in threat intelligence feed', 'critical', 'blocked', 'threat_intel');
                return;
            }
        }
        
        // Skip static files EARLY - before rate limiting and other checks
        // Static files don't need security scanning or rate limiting
        if ($this->is_static_file($this->request_data['uri'] ?? '')) {
            return; // Silently allow, no logging needed for static files
        }
        
        // Skip WordPress internal requests (cron, heartbeat)
        if ($this->should_skip_waf()) {
            return;
        }
        
        // Country blocking check
        $country_blocker = new \VietShield\Firewall\CountryBlocker();
        $country_result = $country_blocker->check($ip);
        
        // Get country for logging
        $country = $country_result['country'] ?? $country_blocker->get_country($ip);
        $this->request_data['country'] = $country;
        
        if ($country_result['blocked']) {
            $this->block_request(
                'country_blocked',
                $country_result['reason'],
                'medium',
                'blocked',
                'country_block',
                $country
            );
            return;
        }
        
        // Rate limiting check (only for dynamic requests)
        if ($this->get_option('rate_limiting_enabled', true)) {
            $rate_limiter = new \VietShield\Firewall\RateLimiter();
            $rate_result = $rate_limiter->check($ip, $this->request_data);
            
            if ($rate_result['blocked']) {
                // Include rate info in matched pattern for logging
                $rate_info = json_encode([
                    'endpoint' => $rate_result['endpoint'] ?? 'global',
                    'current' => $rate_result['current_count'] ?? 0,
                    'limit' => $rate_result['limit'] ?? 0,
                    'window' => $rate_result['window'] ?? 60,
                ]);
                $this->block_request('rate_limited', $rate_info, 'medium', 'rate_limited');
                return;
            }
        }
        
        // Run threat detection
        $firewall_mode = $this->get_option('firewall_mode', 'protecting');
        $threats = $this->threat_detector->detect($this->request_data);
        
        if (!empty($threats)) {
            $primary_threat = $threats[0]; // Most severe threat
            
            if ($firewall_mode === 'learning') {
                // Learning mode - log but don't block
                $this->log_request(
                    'monitored',
                    $primary_threat['rule_id'],
                    $primary_threat['type'],
                    $primary_threat['severity']
                );
            } else {
                // Protecting mode - block
                $this->block_request(
                    $primary_threat['rule_id'],
                    $primary_threat['matched'],
                    $primary_threat['severity'],
                    'blocked',
                    $primary_threat['type']
                );
                
                // Auto-block IP if threshold reached
                $this->maybe_auto_block_ip($ip);
            }
            return;
        }
        
        // No threats detected - log if enabled (with country)
        if ($this->get_option('log_all_traffic', false)) {
            // Get country for logging even if not blocking
            if (empty($this->request_data['country'])) {
                $country_blocker = new \VietShield\Firewall\CountryBlocker();
                $this->request_data['country'] = $country_blocker->get_country($ip);
            }
            $this->log_request('allowed', '', '', 'low');
        }
    }
    
    /**
     * Block the request
     */
    private function block_request($rule_id, $matched, $severity, $action = 'blocked', $attack_type = '', $country = null) {
        // Generate Block ID
        $block_id = substr(md5(time() . microtime(true) . ($this->request_data['ip'] ?? '') . $rule_id), 0, 12);
        
        // Log the blocked request with Block ID (do this first to ensure it's saved)
        $log_id = $this->log_request($action, $rule_id, $attack_type, $severity, $matched, $country, $block_id);
        
        // Queue IP for Threats Sharing (always enabled, cannot be disabled)
        $this->queue_threat_for_sharing($this->request_data['ip'] ?? '', $matched, $attack_type, $severity);
        
        // Ensure database is flushed before exit
        if (function_exists('wp_cache_flush')) {
            wp_cache_flush();
        }
        
        // Send block response with Block ID
        $this->response_handler->block([
            'rule_id' => $rule_id,
            'matched' => $matched,
            'severity' => $severity,
            'attack_type' => $attack_type,
            'ip' => $this->request_data['ip'],
            'block_id' => $block_id
        ]);
    }
    
    /**
     * Queue threat IP for sharing with Intelligence API
     */
    private function queue_threat_for_sharing($ip, $reason, $attack_type, $severity) {
        // Only queue if IP is valid and not whitelisted
        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return;
        }
        
        // Skip private/local IPs
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return;
        }
        
        // Skip if IP is whitelisted
        $ip_manager = new \VietShield\Firewall\IPManager();
        if ($ip_manager->is_whitelisted($ip)) {
            return;
        }
        
        // Get metadata from request data (if available)
        $metadata = [
            'country_code' => $this->request_data['country_code'] ?? '',
            'as_number' => $this->request_data['as_number'] ?? '',
            'organization' => $this->request_data['as_name'] ?? '',
        ];
        
        // If metadata is empty, try to get from threat intel table or existing logs
        if (empty($metadata['country_code']) && empty($metadata['as_number'])) {
            $metadata = $this->get_ip_metadata_quick($ip);
        }
        
        // Prepare reason
        if (empty($reason)) {
            $reason = $attack_type ? ucfirst($attack_type) . ' attack detected' : 'Malicious activity detected';
        }
        
        // Queue IP for submission (metadata can be empty, will be enriched during submission)
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-threats-sharing.php';
        \VietShield\Firewall\ThreatsSharing::queue_ip($ip, $reason, $attack_type, $severity, $metadata);
    }
    
    /**
     * Get IP metadata quickly (from cache/threat intel table, no API call)
     * 
     * @param string $ip
     * @return array
     */
    private function get_ip_metadata_quick($ip) {
        global $wpdb;
        
        // Try threat intelligence table first (fastest)
        $threat_table = $wpdb->prefix . 'vietshield_threat_intel';
        $threat_data = $wpdb->get_row($wpdb->prepare(
            "SELECT country_code, as_number, organization 
             FROM {$threat_table} 
             WHERE ip_address = %s 
             LIMIT 1",
            $ip
        ), ARRAY_A);
        
        if ($threat_data) {
            $as_number_raw = $threat_data['as_number'] ?? '';
            $organization = $threat_data['organization'] ?? '';
            
            // Parse AS info if needed
            $as_number = $as_number_raw;
            $as_name = $organization;
            
            if (preg_match('/^AS(\d+)\s+(.+)$/i', $as_number_raw, $matches)) {
                $as_number = 'AS' . $matches[1];
                $as_name = empty($organization) ? trim($matches[2]) : $organization;
            } elseif (preg_match('/^AS(\d+)$/i', $as_number_raw)) {
                $as_number = $as_number_raw;
            }
            
            return [
                'country_code' => $threat_data['country_code'] ?? '',
                'as_number' => $as_number,
                'organization' => $as_name,
            ];
        }
        
        // Try existing logs (recent entries)
        $log_table = $wpdb->prefix . 'vietshield_logs';
        $existing_log = $wpdb->get_row($wpdb->prepare(
            "SELECT country_code, as_number, as_name 
             FROM {$log_table} 
             WHERE ip = %s 
               AND (country_code != '' OR as_number != '')
             ORDER BY id DESC 
             LIMIT 1",
            $ip
        ), ARRAY_A);
        
        if ($existing_log) {
            return [
                'country_code' => $existing_log['country_code'] ?? '',
                'as_number' => $existing_log['as_number'] ?? '',
                'organization' => $existing_log['as_name'] ?? '',
            ];
        }
        
        // Return empty - will be enriched during submission
        return [
            'country_code' => '',
            'as_number' => '',
            'organization' => '',
        ];
    }
    
    /**
     * Log request
     */
    private function log_request($action, $rule_id = '', $attack_type = '', $severity = 'low', $matched = '', $country = null, $block_id = '') {
        if ($action === 'allowed' && !$this->get_option('log_all_traffic', false)) {
            return;
        }
        
        // Always log blocked requests by default (unless explicitly disabled)
        if ($action === 'blocked') {
            $log_blocked = $this->get_option('log_blocked_only', true);
            // Handle both boolean and string values
            if ($log_blocked === false || $log_blocked === '0' || $log_blocked === 0) {
                return;
            }
        }
        
        // Use provided country or get from request_data
        if ($country === null) {
            $country = $this->request_data['country'] ?? '';
        }
        
        $log_data = [
            'ip' => $this->request_data['ip'] ?? '',
            'country' => $country,
            'request_uri' => $this->request_data['uri'] ?? '',
            'request_method' => $this->request_data['method'] ?? 'GET',
            'user_agent' => $this->request_data['user_agent'] ?? '',
            'referer' => $this->request_data['referer'] ?? '',
            'post_data' => $this->get_post_data_for_log(),
            'action' => $action,
            'rule_id' => $rule_id,
            'rule_matched' => $matched,
            'attack_type' => $attack_type,
            'severity' => $severity,
        ];
        
        // Add Block ID if provided (for blocked requests)
        if (!empty($block_id)) {
            $log_data['block_id'] = $block_id;
        }
        
        $this->logger->log($log_data);
    }
    
    /**
     * Check if should skip WAF for WordPress internal requests
     */
    private function should_skip_waf() {
        $uri = $this->request_data['uri'] ?? '';
        
        // Skip WordPress cron
        if (strpos($uri, 'wp-cron.php') !== false) {
            return true;
        }
        
        // Skip heartbeat and admin AJAX requests
        if (defined('DOING_AJAX') && DOING_AJAX) {
            // Skip heartbeat
            if (isset($_POST['action']) && $_POST['action'] === 'heartbeat') {
                return true;
            }
            
            // Skip all AJAX requests from admin (check referer)
            $referer = $_SERVER['HTTP_REFERER'] ?? '';
            if (preg_match('#/wp-admin/#', $referer)) {
                return true;
            }
            
            // Skip AJAX requests to admin-ajax.php
            if (strpos($uri, 'admin-ajax.php') !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Check if URI is for a static file
     * 
     * @param string $uri Request URI
     * @return bool
     */
    private function is_static_file($uri) {
        $path = wp_parse_url($uri, PHP_URL_PATH);
        if (!$path) {
            return false;
        }
        
        $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        
        // Static file extensions - no WAF or rate limit checks needed
        $static_extensions = [
            // Stylesheets
            'css', 'less', 'scss', 'sass',
            // JavaScript
            'js', 'mjs', 'jsx', 'ts', 'tsx',
            // Images
            'jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'ico', 'bmp', 'tiff', 'avif',
            // Fonts
            'woff', 'woff2', 'ttf', 'otf', 'eot',
            // Media
            'mp3', 'mp4', 'webm', 'ogg', 'wav', 'avi', 'mov', 'wmv', 'flv',
            // Maps
            'map',
        ];
        
        return in_array($extension, $static_extensions);
    }
    
    /**
     * Check if current user is whitelisted admin
     */
    private function is_whitelisted_admin() {
        if (!$this->get_option('whitelist_admins', true)) {
            return false;
        }
        
        // Check if logged in admin
        if (function_exists('is_user_logged_in') && is_user_logged_in()) {
            if (function_exists('current_user_can') && current_user_can('manage_options')) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Early check for admin request using raw server variables
     * This is called before request analysis for faster detection
     * Simple and reliable pattern matching
     */
    private function is_admin_request_early() {
        // Get all relevant server variables
        $script_name = $_SERVER['SCRIPT_NAME'] ?? '';
        $php_self = $_SERVER['PHP_SELF'] ?? '';
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        $query_string = $_SERVER['QUERY_STRING'] ?? '';
        
        // Simple and reliable: check if ANY contains /wp-admin/
        // This is the most reliable pattern for WordPress admin
        if (strpos($script_name, '/wp-admin/') !== false ||
            strpos($php_self, '/wp-admin/') !== false ||
            strpos($request_uri, '/wp-admin/') !== false ||
            strpos($query_string, '/wp-admin/') !== false) {
            return true;
        }
        
        // Check for admin.php in query string
        if (strpos($query_string, 'admin.php') !== false) {
            return true;
        }
        
        // Check for admin-ajax.php and admin-post.php
        if (strpos($request_uri, 'admin-ajax.php') !== false ||
            strpos($request_uri, 'admin-post.php') !== false ||
            strpos($script_name, 'admin-ajax.php') !== false ||
            strpos($script_name, 'admin-post.php') !== false) {
            
            // If referer is from admin, exclude it
            $referer = $_SERVER['HTTP_REFERER'] ?? '';
            if (strpos($referer, '/wp-admin/') !== false) {
                return true;
            }
            
            // If user has WordPress login cookie, likely admin request
            foreach ($_COOKIE as $key => $value) {
                if (strpos($key, 'wordpress_logged_in_') === 0) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Check if this is a WordPress admin request
     * Admin requests should be excluded from total requests count
     */
    private function is_admin_request() {
        // Check SCRIPT_NAME and PHP_SELF (most reliable for admin.php)
        $script_name = $_SERVER['SCRIPT_NAME'] ?? '';
        $php_self = $_SERVER['PHP_SELF'] ?? '';
        
        // Check if script is admin.php
        if (strpos($script_name, '/wp-admin/admin.php') !== false || 
            strpos($php_self, '/wp-admin/admin.php') !== false) {
            return true;
        }
        
        // Check original REQUEST_URI before decoding (more reliable)
        $original_uri = $_SERVER['REQUEST_URI'] ?? '';
        
        // Primary check: URI contains /wp-admin/ (most reliable)
        // This catches: /wp-admin/admin.php, /wp-admin/ajax.php, etc.
        if (preg_match('#/wp-admin/#', $original_uri)) {
            return true;
        }
        
        // Also check decoded URI
        $uri = $this->request_data['uri'] ?? '';
        if (preg_match('#/wp-admin/#', $uri)) {
            return true;
        }
        
        // Check query string for admin.php (catches ?page=... in admin)
        $query_string = $_SERVER['QUERY_STRING'] ?? '';
        if (strpos($query_string, 'admin.php') !== false) {
            return true;
        }
        
        // Check if WordPress admin cookie exists (wordpress_logged_in_*)
        // This indicates user is logged in, and if URI has admin pattern, it's likely admin
        $has_wp_cookie = false;
        foreach ($_COOKIE as $key => $value) {
            if (strpos($key, 'wordpress_logged_in_') === 0) {
                $has_wp_cookie = true;
                break;
            }
        }
        
        if ($has_wp_cookie) {
            // User is logged in, check if URI suggests admin area
            if (strpos($original_uri, 'admin') !== false || strpos($uri, 'admin') !== false) {
                return true;
            }
            // Also check for common admin patterns
            if (strpos($original_uri, 'admin-ajax.php') !== false || 
                strpos($original_uri, 'admin-post.php') !== false) {
                return true;
            }
        }
        
        // Check if this is an admin AJAX request
        if (defined('DOING_AJAX') && DOING_AJAX) {
            // Check referer for admin area
            if (isset($_SERVER['HTTP_REFERER']) && preg_match('#/wp-admin/#', $_SERVER['HTTP_REFERER'])) {
                return true;
            }
        }
        
        // Check if WordPress is_admin() function is available and returns true
        // This only works if WordPress has loaded
        if (function_exists('is_admin') && is_admin()) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Auto-block IP if it reaches attack threshold
     */
    private function maybe_auto_block_ip($ip) {
        global $wpdb;
        
        $threshold = $this->get_option('auto_block_threshold', 10);
        $duration = $this->get_option('auto_block_duration', 3600);
        
        if ($threshold <= 0) {
            return;
        }
        
        // Count recent attacks from this IP
        $table = $wpdb->prefix . 'vietshield_logs';
        $count = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $table 
             WHERE ip = %s 
             AND action = 'blocked' 
             AND timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)",
            $ip
        ));
        
        if ($count >= $threshold) {
            $ip_manager = new \VietShield\Firewall\IPManager();
            $ip_manager->add_to_blacklist($ip, 'temporary', "Auto-blocked after {$count} attacks", $duration);
        }
    }
    
    /**
     * Check if user is logged in (Early check via cookie)
     * 
     * @return bool
     */
    private function is_user_logged_in_early() {
        foreach ($_COOKIE as $key => $value) {
            if (strpos($key, 'wordpress_logged_in_') === 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get client IP with proxy support
     */
    private function get_client_ip() {
        $trusted_proxies = $this->get_option('trusted_proxies', []);
        
        // Check for proxy headers
        $headers = [
            'HTTP_CF_CONNECTING_IP',     // Cloudflare
            'HTTP_X_REAL_IP',            // Nginx proxy
            'HTTP_X_FORWARDED_FOR',      // Standard proxy
            'HTTP_CLIENT_IP',
            'REMOTE_ADDR'
        ];
        
        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = $_SERVER[$header];
                
                // X-Forwarded-For can contain multiple IPs
                if ($header === 'HTTP_X_FORWARDED_FOR') {
                    $ips = explode(',', $ip);
                    $ip = trim($ips[0]);
                }
                
                // Validate IP
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
    
    /**
     * Get POST data for logging
     * Only log if there's actual data
     */
    private function get_post_data_for_log() {
        if (!isset($this->request_data['post']) || empty($this->request_data['post'])) {
            // Check raw body for JSON/XML requests
            $raw_body = $this->request_data['raw_body'] ?? '';
            if (!empty($raw_body) && strlen(trim($raw_body)) > 0) {
                return $raw_body;
            }
            return '';
        }
        
        $post_data = $this->request_data['post'];
        
        // If it's an empty array, don't log it
        if (is_array($post_data) && count($post_data) === 0) {
            return '';
        }
        
        // For regular POST, return JSON encoded
        return json_encode($post_data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }
    
    /**
     * Get option with default
     */
    private function get_option($key, $default = null) {
        return $this->options[$key] ?? $default;
    }
    
    /**
     * Get request data
     */
    public function get_request_data() {
        return $this->request_data;
    }
}
