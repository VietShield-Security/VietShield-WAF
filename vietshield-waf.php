<?php
/**
 * Plugin Name: VietShield WAF
 * Plugin URI: https://vietshield.org
 * Description: High-performance Web Application Firewall (WAF) for WordPress. Protects against SQL Injection, XSS, RCE, and more with advanced traffic analysis and real-time blocking.
 * Version: 1.0.2
 * Author: VietShield Security
 * Author URI: https://github.com/VietShield-Security
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: vietshield-waf
 * Domain Path: /languages
 * Requires at least: 5.0
 * Requires PHP: 7.4
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Plugin constants
define('VIETSHIELD_VERSION', '1.0.2');
define('VIETSHIELD_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('VIETSHIELD_PLUGIN_URL', plugin_dir_url(__FILE__));
define('VIETSHIELD_PLUGIN_BASENAME', plugin_basename(__FILE__));
define('VIETSHIELD_DB_VERSION', '1.1.0');

/**
 * Autoloader for plugin classes
 */
spl_autoload_register(function ($class) {
    $prefix = 'VietShield\\';
    $base_dir = VIETSHIELD_PLUGIN_DIR . 'includes/';

    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }

    $relative_class = substr($class, $len);
    $relative_class = strtolower($relative_class);
    $relative_class = str_replace('\\', '/', $relative_class);
    $relative_class = str_replace('_', '-', $relative_class);
    
    // Map class names to file paths
    $class_map = [
        'waf/wafengine' => 'waf/class-waf-engine.php',
        'waf/requestanalyzer' => 'waf/class-request-analyzer.php',
        'waf/rulematcher' => 'waf/class-rule-matcher.php',
        'waf/threatdetector' => 'waf/class-threat-detector.php',
        'waf/responsehandler' => 'waf/class-response-handler.php',
        'logging/trafficlogger' => 'logging/class-traffic-logger.php',
        'firewall/ipmanager' => 'firewall/class-ip-manager.php',
        'firewall/ratelimiter' => 'firewall/class-rate-limiter.php',
        'scanner/filescanner' => 'scanner/class-file-scanner.php',
    ];
    
    if (isset($class_map[$relative_class])) {
        $file = $base_dir . $class_map[$relative_class];
    } else {
        $file = $base_dir . 'class-' . $relative_class . '.php';
    }

    if (file_exists($file)) {
        require $file;
    }
});

/**
 * Load required files
 */
require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-vietshield-activator.php';
require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-vietshield-deactivator.php';

/**
 * Activation hook
 */
register_activation_hook(__FILE__, ['VietShield_Activator', 'activate']);

/**
 * Deactivation hook
 */
register_deactivation_hook(__FILE__, ['VietShield_Deactivator', 'deactivate']);

/**
 * Initialize WAF as early as possible
 * Priority -999999 ensures it runs before almost everything else
 */
add_action('muplugins_loaded', 'vietshield_init_waf_early', -999999);
add_action('plugins_loaded', 'vietshield_init_waf_early', -999999);

function vietshield_init_waf_early() {
    static $initialized = false;
    
    if ($initialized) {
        return;
    }
    $initialized = true;
    
    // Check if WAF is enabled
    $options = get_option('vietshield_options', []);
    if (isset($options['waf_enabled']) && !$options['waf_enabled']) {
        return;
    }
    
    // Load and initialize WAF engine
    require_once VIETSHIELD_PLUGIN_DIR . 'includes/waf/class-waf-engine.php';
    $waf = VietShield\WAF\WAFEngine::get_instance();
    $waf->init();
}

/**
 * Initialize admin and integrations
 */
add_action('plugins_loaded', 'vietshield_init');

function vietshield_init() {
    // Ensure DB schema is up to date
    if (get_option('vietshield_db_version') !== VIETSHIELD_DB_VERSION) {
        VietShield_Activator::maybe_upgrade();
    }

    // Load text domain (needed for self-hosted plugins)
    // phpcs:ignore PluginCheck.CodeAnalysis.DiscouragedFunctions.load_plugin_textdomainFound -- Required for self-hosted translations
    load_plugin_textdomain('vietshield-waf', false, dirname(VIETSHIELD_PLUGIN_BASENAME) . '/languages');
    
    // Initialize Login Security
    $options = get_option('vietshield_options', []);
    if (isset($options['login_security_enabled']) && $options['login_security_enabled']) {
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/integrations/class-login-security.php';
        new \VietShield\Integrations\LoginSecurity();
    }
    
    // Initialize admin
    if (is_admin()) {
        require_once VIETSHIELD_PLUGIN_DIR . 'admin/class-admin-dashboard.php';
        new VietShield_Admin_Dashboard();
    }
    
    // Schedule threat intelligence sync if enabled
    require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-threat-intelligence.php';
    \VietShield\Firewall\ThreatIntelligence::schedule_sync();
}

/**
 * Cron schedules
 */
add_filter('cron_schedules', function ($schedules) {
    if (!isset($schedules['weekly'])) {
        $schedules['weekly'] = [
            'interval' => 7 * DAY_IN_SECONDS,
            'display' => __('Once Weekly', 'vietshield-waf'),
        ];
    }
    
    // 5 minutes interval for Threats Sharing
    if (!isset($schedules['vietshield_5minutes'])) {
        $schedules['vietshield_5minutes'] = [
            'interval' => 5 * MINUTE_IN_SECONDS,
            'display' => __('Every 5 Minutes', 'vietshield-waf'),
        ];
    }
    
    // Threat Intelligence intervals
    if (!isset($schedules['vietshield_threat_intel_interval'])) {
        // This will be set dynamically based on category
        $schedules['vietshield_threat_intel_interval'] = [
            'interval' => 24 * HOUR_IN_SECONDS, // Default: daily
            'display' => __('VietShield Threat Intel Interval', 'vietshield-waf'),
        ];
    }
    
    return $schedules;
});

/**
 * Scheduled file scan
 */
add_action('vietshield_file_scan_event', function () {
    require_once VIETSHIELD_PLUGIN_DIR . 'includes/scanner/class-file-scanner.php';
    $scanner = new \VietShield\Scanner\FileScanner();
    $scanner->run_scan();
});

/**
 * Scheduled malware scan
 */
add_action('vietshield_malware_scan_event', function () {
    require_once VIETSHIELD_PLUGIN_DIR . 'includes/scanner/class-malware-scanner.php';
    $scanner = new \VietShield\Scanner\MalwareScanner();
    $options = get_option('vietshield_options', []);
    $scope = $options['malware_scan_scope'] ?? 'all';
    $scanner->run_scan($scope);
});

/**
 * Scheduled threat intelligence sync
 */
add_action('vietshield_threat_intel_sync', function () {
    require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-threat-intelligence.php';
    \VietShield\Firewall\ThreatIntelligence::cron_sync();
});

/**
 * Initial threat intelligence sync after activation
 */
add_action('vietshield_threat_intel_initial_sync', function () {
    require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-threat-intelligence.php';
    $options = get_option('vietshield_options', []);
    
    // Only sync if threat intel is enabled
    if (!empty($options['threat_intel_enabled']) && !empty($options['threat_intel_category'])) {
        $threat_intel = new \VietShield\Firewall\ThreatIntelligence();
        $result = $threat_intel->sync_feed($options['threat_intel_category']);
        
        // Log result for debugging
        if ($result && isset($result['success'])) {
            if ($result['success']) {
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
                error_log('VietShield: Threat Intelligence initial sync completed successfully. IPs: ' . ($result['inserted'] ?? 0));
            } else {
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
                error_log('VietShield: Threat Intelligence initial sync failed: ' . ($result['error'] ?? 'Unknown error'));
            }
        }
    }
});

/**
 * Scheduled tasks
 */
add_action('vietshield_cleanup_logs', function () {
    require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-scheduled-tasks.php';
    VietShield_Scheduled_Tasks::cleanup_logs();
});

add_action('vietshield_aggregate_stats', function () {
    require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-scheduled-tasks.php';
    VietShield_Scheduled_Tasks::aggregate_stats();
});

add_action('vietshield_update_threat_feed', function () {
    require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-scheduled-tasks.php';
    VietShield_Scheduled_Tasks::update_threat_feed();
});

/**
 * Threats Sharing - Submit queue
 */
add_action('vietshield_submit_threats', function () {
    require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-threats-sharing.php';
    \VietShield\Firewall\ThreatsSharing::submit_queue();
});

/**
 * Weekly maintenance tasks
 */
add_action('vietshield_maintenance', function () {
    require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-scheduled-tasks.php';
    VietShield_Scheduled_Tasks::maintenance();
});

/**
 * Daily IP whitelist sync (Googlebot)
 */
add_action('vietshield_ip_whitelist_sync', function () {
    require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-ip-whitelist-sync.php';
    \VietShield\Firewall\IPWhitelistSync::sync_all();
});

/**
 * Sync missing IP metadata (Country, ASN) - Background Task
 */
add_action('vietshield_sync_ip_metadata', function () {
    require_once VIETSHIELD_PLUGIN_DIR . 'includes/logging/class-traffic-logger.php';
    $logger = new \VietShield\Logging\TrafficLogger();
    $logger->sync_missing_metadata();
});

/**
 * Ensure cron jobs are scheduled (Auto-repair)
 */
add_action('init', function() {
    // Threats Sharing - Update to 5 minutes interval
    // Clear any existing scheduled events with old interval
    $timestamp = wp_next_scheduled('vietshield_submit_threats');
    if ($timestamp !== false) {
        wp_unschedule_event($timestamp, 'vietshield_submit_threats');
    }
    // Clear all scheduled events for this hook (in case of duplicates)
    wp_clear_scheduled_hook('vietshield_submit_threats');
    // Schedule with new 5-minute interval
    if (!wp_next_scheduled('vietshield_submit_threats')) {
        wp_schedule_event(time(), 'vietshield_5minutes', 'vietshield_submit_threats');
    }
    
    // IP Metadata Sync - Every 5 minutes
    if (!wp_next_scheduled('vietshield_sync_ip_metadata')) {
        wp_schedule_event(time(), 'vietshield_5minutes', 'vietshield_sync_ip_metadata');
    }

    // Aggregate Stats (Hourly)
    if (!wp_next_scheduled('vietshield_aggregate_stats')) {
        wp_schedule_event(time(), 'hourly', 'vietshield_aggregate_stats');
    }

    // Googlebot IP Whitelist Sync (Daily)
    if (!wp_next_scheduled('vietshield_ip_whitelist_sync')) {
        wp_schedule_event(time(), 'daily', 'vietshield_ip_whitelist_sync');
    }
});

/**
 * Add settings link on plugin page
 */
add_filter('plugin_action_links_' . VIETSHIELD_PLUGIN_BASENAME, function ($links) {
    $settings_link = '<a href="' . admin_url('admin.php?page=vietshield-waf') . '">' . __('Settings', 'vietshield-waf') . '</a>';
    array_unshift($links, $settings_link);
    return $links;
});
