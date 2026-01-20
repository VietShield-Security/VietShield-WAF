<?php
/**
 * Admin Dashboard
 * 
 * @package VietShield_WAF
 */

if (!defined('ABSPATH')) {
    exit;
}

class VietShield_Admin_Dashboard {
    
    /**
     * Options
     */
    private $options;
    
    /**
     * Constructor
     */
    public function __construct() {
        $this->options = get_option('vietshield_options', []);
        
        // Initialize wizard for first-time install
        // Always load wizard if not completed - don't rely on transients which may expire
        $wizard_completed = get_option('vietshield_wizard_completed', false);
        
        if (!$wizard_completed) {
            require_once VIETSHIELD_PLUGIN_DIR . 'admin/class-admin-wizard.php';
            new VietShield_Admin_Wizard();
        }
        
        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_assets']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('wp_ajax_vietshield_get_stats', [$this, 'ajax_get_stats']);
        add_action('wp_ajax_vietshield_get_logs', [$this, 'ajax_get_logs']);
        add_action('wp_ajax_vietshield_get_log_details', [$this, 'ajax_get_log_details']);
        add_action('wp_ajax_vietshield_get_login_stats', [$this, 'ajax_get_login_stats']);
        add_action('wp_ajax_vietshield_start_file_scan', [$this, 'ajax_start_file_scan']);
        add_action('wp_ajax_vietshield_get_file_scan', [$this, 'ajax_get_file_scan']);
        add_action('wp_ajax_vietshield_start_malware_scan', [$this, 'ajax_start_malware_scan']);
        add_action('wp_ajax_vietshield_get_malware_scan', [$this, 'ajax_get_malware_scan']);
        add_action('wp_ajax_vietshield_clear_malware_history', [$this, 'ajax_clear_malware_history']);
        add_action('wp_ajax_vietshield_clear_file_history', [$this, 'ajax_clear_file_history']);
        add_action('wp_ajax_vietshield_sync_threat_intel', [$this, 'ajax_sync_threat_intel']);
        add_action('wp_ajax_vietshield_clear_threat_intel', [$this, 'ajax_clear_threat_intel']);
        add_action('wp_ajax_vietshield_get_threat_intel_status', [$this, 'ajax_get_threat_intel_status']);
        add_action('wp_ajax_vietshield_sync_early_blocker', [$this, 'ajax_sync_early_blocker']);
        add_action('wp_ajax_vietshield_block_ip', [$this, 'ajax_block_ip']);
        add_action('wp_ajax_vietshield_unblock_ip', [$this, 'ajax_unblock_ip']);
        add_action('wp_ajax_vietshield_clear_logs', [$this, 'ajax_clear_logs']);
        add_action('wp_ajax_vietshield_sync_ip_whitelist', [$this, 'ajax_sync_ip_whitelist']);
        add_action('update_option_vietshield_options', [$this, 'handle_options_update'], 10, 2);
        
        // Show activation notice
        if (get_transient('vietshield_activated')) {
            add_action('admin_notices', [$this, 'activation_notice']);
            delete_transient('vietshield_activated');
        }
        
        // Trigger threat intelligence initial sync on first admin page load after activation
        // Use priority 5 to run early but after WordPress is fully loaded
        add_action('admin_init', [$this, 'maybe_sync_threat_intel'], 5);
    }
    
    /**
     * Add admin menu
     */
    public function add_admin_menu() {
        add_menu_page(
            __('VietShield WAF', 'vietshield-waf'),
            __('VietShield WAF', 'vietshield-waf'),
            'manage_options',
            'vietshield-waf',
            [$this, 'render_dashboard'],
            'dashicons-shield',
            65
        );
        
        add_submenu_page(
            'vietshield-waf',
            __('Dashboard', 'vietshield-waf'),
            __('Dashboard', 'vietshield-waf'),
            'manage_options',
            'vietshield-waf',
            [$this, 'render_dashboard']
        );
        
        add_submenu_page(
            'vietshield-waf',
            __('Firewall', 'vietshield-waf'),
            __('Firewall', 'vietshield-waf'),
            'manage_options',
            'vietshield-firewall',
            [$this, 'render_firewall']
        );
        
        add_submenu_page(
            'vietshield-waf',
            __('Live Traffic', 'vietshield-waf'),
            __('Live Traffic', 'vietshield-waf'),
            'manage_options',
            'vietshield-traffic',
            [$this, 'render_traffic']
        );
        
        add_submenu_page(
            'vietshield-waf',
            __('Login Security', 'vietshield-waf'),
            __('Login Security', 'vietshield-waf'),
            'manage_options',
            'vietshield-login',
            [$this, 'render_login_security']
        );

        add_submenu_page(
            'vietshield-waf',
            __('File Scanner', 'vietshield-waf'),
            __('File Scanner', 'vietshield-waf'),
            'manage_options',
            'vietshield-file-scanner',
            [$this, 'render_file_scanner']
        );

        add_submenu_page(
            'vietshield-waf',
            __('Malware Scanner', 'vietshield-waf'),
            __('Malware Scanner', 'vietshield-waf'),
            'manage_options',
            'vietshield-malware-scanner',
            [$this, 'render_malware_scanner']
        );
        
        add_submenu_page(
            'vietshield-waf',
            __('Settings', 'vietshield-waf'),
            __('Settings', 'vietshield-waf'),
            'manage_options',
            'vietshield-settings',
            [$this, 'render_settings']
        );
    }
    
    /**
     * Enqueue admin assets
     */
    public function enqueue_assets($hook) {
        if (strpos($hook, 'vietshield') === false) {
            return;
        }

        $css_file = VIETSHIELD_PLUGIN_DIR . 'admin/css/admin-style.css';
        $js_file = VIETSHIELD_PLUGIN_DIR . 'admin/js/admin-scripts.js';
        $css_version = file_exists($css_file) ? filemtime($css_file) : VIETSHIELD_VERSION;
        $js_version = file_exists($js_file) ? filemtime($js_file) : VIETSHIELD_VERSION;
        
        wp_enqueue_style(
            'vietshield-admin',
            VIETSHIELD_PLUGIN_URL . 'admin/css/admin-style.css',
            [],
            $css_version
        );
        
        wp_enqueue_script(
            'vietshield-admin',
            VIETSHIELD_PLUGIN_URL . 'admin/js/admin-scripts.js',
            ['jquery'],
            $js_version,
            true
        );
        
        wp_localize_script('vietshield-admin', 'vietshieldAdmin', [
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('vietshield_admin'),
            'strings' => [
                'confirmBlock' => __('Are you sure you want to block this IP?', 'vietshield-waf'),
                'confirmUnblock' => __('Are you sure you want to unblock this IP?', 'vietshield-waf'),
                'confirmClearLogs' => __('Are you sure you want to clear all logs?', 'vietshield-waf'),
                'pause' => __('Pause', 'vietshield-waf'),
                'resume' => __('Resume', 'vietshield-waf'),
                'liveStatus' => __('Live - Auto-refreshing every 5 seconds', 'vietshield-waf'),
                'pausedStatus' => __('Paused', 'vietshield-waf'),
                'noData' => __('No traffic data found', 'vietshield-waf'),
                'page' => __('Page', 'vietshield-waf'),
                'of' => __('of', 'vietshield-waf'),
            ]
        ]);
    }
    
    /**
     * Register settings
     */
    public function register_settings() {
        register_setting('vietshield_options', 'vietshield_options', [
            'sanitize_callback' => [$this, 'sanitize_options']
        ]);
    }
    
    /**
     * Check if wizard should be shown and redirect if needed
     * @return bool True if redirected, false otherwise
     */
    private function maybe_redirect_to_wizard() {
        $wizard_completed = get_option('vietshield_wizard_completed', false);
        
        if (!$wizard_completed) {
            wp_safe_redirect(admin_url('admin.php?page=vietshield-wizard'));
            exit;
        }
        return false;
    }
    
    /**
     * Sanitize options
     */
    public function sanitize_options($input) {
        $sanitized = [];
        
        // Boolean options
        $bool_options = [
            'waf_enabled', 'log_all_traffic', 'log_blocked_only',
            'block_sqli', 'block_xss', 'block_rce', 'block_lfi',
            'block_bad_bots', 'rate_limiting_enabled', 'block_xmlrpc',
            'block_author_scan', 'whitelist_admins', 'email_alerts',
            'country_blocking_enabled', 'block_unknown_countries',
            'login_security_enabled', 'login_notifications_enabled', 'login_honeypot_enabled',
            'file_scanner_enabled', 'malware_scanner_enabled', 'threat_intel_enabled'
        ];
        
        foreach ($bool_options as $opt) {
            $sanitized[$opt] = isset($input[$opt]) ? (bool) $input[$opt] : false;
        }
        
        // String options
        $sanitized['firewall_mode'] = sanitize_text_field($input['firewall_mode'] ?? 'protecting');
        $sanitized['alert_email'] = sanitize_email($input['alert_email'] ?? '');

        // File scanner schedule
        $schedule = sanitize_text_field($input['file_scan_schedule'] ?? 'weekly');
        $allowed_schedules = ['manual', 'daily', 'weekly'];
        $sanitized['file_scan_schedule'] = in_array($schedule, $allowed_schedules, true) ? $schedule : 'weekly';

        // Malware scanner schedule
        $malware_schedule = sanitize_text_field($input['malware_scan_schedule'] ?? 'weekly');
        $sanitized['malware_scan_schedule'] = in_array($malware_schedule, $allowed_schedules, true) ? $malware_schedule : 'weekly';

        // Malware scan scope
        $scope = sanitize_text_field($input['malware_scan_scope'] ?? 'all');
        $allowed_scopes = ['all', 'themes', 'plugins', 'uploads'];
        $sanitized['malware_scan_scope'] = in_array($scope, $allowed_scopes, true) ? $scope : 'all';

        // Threat Intelligence category
        $threat_category = sanitize_text_field($input['threat_intel_category'] ?? '');
        $allowed_categories = ['1d', '3d', '7d', '14d', '30d', ''];
        $sanitized['threat_intel_category'] = in_array($threat_category, $allowed_categories, true) ? $threat_category : '';
        
        // Timezone option
        if (!empty($input['log_timezone'])) {
            // Validate timezone
            $timezone = sanitize_text_field($input['log_timezone']);
            if (in_array($timezone, timezone_identifiers_list()) || $timezone === 'UTC') {
                $sanitized['log_timezone'] = $timezone;
            } else {
                $sanitized['log_timezone'] = get_option('timezone_string') ?: 'UTC';
            }
        } else {
            $sanitized['log_timezone'] = get_option('timezone_string') ?: 'UTC';
        }
        
        // Integer options
        $int_options = [
            'rate_limit_global' => 100,
            'rate_limit_login' => 20,
            'rate_limit_xmlrpc' => 20,
            'auto_block_threshold' => 10,
            'auto_block_duration' => 3600,
            'log_retention_days' => 30,
            'login_max_attempts' => 5,
            'login_time_window' => 900,
            'login_lockout_duration' => 900,
            'login_notification_threshold' => 3,
        ];
        
        foreach ($int_options as $opt => $default) {
            $sanitized[$opt] = isset($input[$opt]) ? absint($input[$opt]) : $default;
        }
        
        // Array options
        if (!empty($input['whitelisted_ips'])) {
            $ips = array_map('trim', explode("\n", $input['whitelisted_ips']));
            $sanitized['whitelisted_ips'] = array_filter($ips, function($ip) {
                return filter_var($ip, FILTER_VALIDATE_IP) || preg_match('/^\d+\.\d+\.\d+\.\d+\/\d+$/', $ip);
            });
        } else {
            $sanitized['whitelisted_ips'] = [];
        }
        
        if (!empty($input['blacklisted_ips'])) {
            $ips = array_map('trim', explode("\n", $input['blacklisted_ips']));
            $sanitized['blacklisted_ips'] = array_filter($ips, function($ip) {
                return filter_var($ip, FILTER_VALIDATE_IP) || preg_match('/^\d+\.\d+\.\d+\.\d+\/\d+$/', $ip);
            });
        } else {
            $sanitized['blacklisted_ips'] = [];
        }
        
        // Country blocking options
        if (!empty($input['blocked_countries']) && is_array($input['blocked_countries'])) {
            // Validate country codes (2 letters uppercase)
            $sanitized['blocked_countries'] = array_filter($input['blocked_countries'], function($code) {
                return preg_match('/^[A-Z]{2}$/', $code);
            });
        } else {
            $sanitized['blocked_countries'] = [];
        }
        
        // RCE Whitelist Patterns
        if (!empty($input['rce_whitelist_patterns'])) {
            // Check if input is already an array (from previous save or default)
            if (is_array($input['rce_whitelist_patterns'])) {
                $patterns = array_map('trim', $input['rce_whitelist_patterns']);
            } else {
                // Input is a string (from textarea), explode by newlines
                $patterns = array_map('trim', explode("\n", $input['rce_whitelist_patterns']));
            }
            
            $sanitized['rce_whitelist_patterns'] = array_filter($patterns, function($pattern) {
                // Validate regex pattern (basic check)
                if (empty($pattern)) {
                    return false;
                }
                // Check if it's a valid regex pattern by testing it
                $test_result = @preg_match($pattern, '');
                return ($test_result !== false || preg_last_error() === PREG_NO_ERROR);
            });
        } else {
            // Use default patterns if empty
            $sanitized['rce_whitelist_patterns'] = [
                '/gclid=/i',
                '/gad_source=/i',
                '/gad_campaignid=/i',
                '/utm_source=/i',
                '/utm_medium=/i',
                '/utm_campaign=/i',
                '/utm_content=/i',
                '/utm_term=/i',
                '/dclid=/i',
                '/gbraid=/i',
                '/wbraid=/i',
                '/safeframe\.googlesyndication\.com/i',
                '/googlesyndication\.com/i',
                '/googleadservices\.com/i',
                '/doubleclick\.net/i',
                '/google-analytics\.com/i',
                '/googletagmanager\.com/i',
                '/[?&](typ|src|mdm|cmp|cnt|trm|id|plt)=/i',
            ];
        }
        
        return $sanitized;
    }
    
    /**
     * Render dashboard page
     */
    public function render_dashboard() {
        $this->maybe_redirect_to_wizard();
        
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/logging/class-traffic-logger.php';
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-threat-intelligence.php';
        
        $logger = new VietShield\Logging\TrafficLogger();
        
        $stats = $logger->get_stats(7);
        $top_ips = $logger->get_top_blocked_ips(10, 7);
        $recent_attacks = $logger->get_recent_attacks(10);
        
        // Enrich recent attacks with IP status
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-ip-manager.php';
        $ip_manager = new \VietShield\Firewall\IPManager();
        
        foreach ($recent_attacks as &$attack) {
            $attack['ip_status'] = 'clean';
            if ($ip_manager->is_whitelisted($attack['ip'])) {
                $attack['ip_status'] = 'whitelisted';
            } elseif ($ip_manager->is_blacklisted($attack['ip'])) {
                // Check if temporary
                $info = $ip_manager->get_ip_info($attack['ip']);
                if ($info && $info['list_type'] === 'temporary') {
                    $attack['ip_status'] = 'temporary';
                } else {
                    $attack['ip_status'] = 'blacklisted';
                }
            }
        }
        unset($attack);
        
        // Get threat intelligence stats
        $threat_intel_synced = \VietShield\Firewall\ThreatIntelligence::get_total_synced_ips();
        $threat_intel_blocked = \VietShield\Firewall\ThreatIntelligence::get_blocked_count(7);
        
        include VIETSHIELD_PLUGIN_DIR . 'admin/views/dashboard.php';
    }
    
    /**
     * Render firewall page
     */
    public function render_firewall() {
        $this->maybe_redirect_to_wizard();
        
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-ip-manager.php';
        $ip_manager = new VietShield\Firewall\IPManager();
        
        $vswaf_whitelist = $ip_manager->get_list('whitelist');
        $vswaf_blacklist = $ip_manager->get_list('blacklist');
        $vswaf_temporary = $ip_manager->get_list('temporary');
        
        include VIETSHIELD_PLUGIN_DIR . 'admin/views/firewall.php';
    }
    
    /**
     * Render live traffic page
     */
    public function render_traffic() {
        $this->maybe_redirect_to_wizard();
        
        include VIETSHIELD_PLUGIN_DIR . 'admin/views/live-traffic.php';
    }
    
    /**
     * Render login security page
     */
    public function render_login_security() {
        $this->maybe_redirect_to_wizard();
        
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/integrations/class-login-security.php';
        $login_security = new \VietShield\Integrations\LoginSecurity();
        
        $stats = $login_security->get_login_stats(7);
        $recent_failed = $login_security->get_recent_failed_attempts(20);
        $top_ips = $login_security->get_top_attacking_ips(10, 7);
        
        include VIETSHIELD_PLUGIN_DIR . 'admin/views/login-security.php';
    }

    /**
     * Render file scanner page
     */
    public function render_file_scanner() {
        $this->maybe_redirect_to_wizard();
        
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/scanner/class-file-scanner.php';
        $vswaf_scanner = new \VietShield\Scanner\FileScanner();
        $vswaf_latest_scan = $vswaf_scanner->get_latest_scan();

        include VIETSHIELD_PLUGIN_DIR . 'admin/views/file-scanner.php';
    }

    /**
     * Render malware scanner page
     */
    public function render_malware_scanner() {
        $this->maybe_redirect_to_wizard();
        
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/scanner/class-malware-scanner.php';
        $vswaf_scanner = new \VietShield\Scanner\MalwareScanner();
        $vswaf_latest_scan = $vswaf_scanner->get_latest_scan();

        include VIETSHIELD_PLUGIN_DIR . 'admin/views/malware-scanner.php';
    }
    
    /**
     * Render settings page
     */
    public function render_settings() {
        $this->maybe_redirect_to_wizard();
        
        include VIETSHIELD_PLUGIN_DIR . 'admin/views/settings.php';
    }
    
    /**
     * Maybe sync threat intelligence on first admin page load
     */
    public function maybe_sync_threat_intel() {
        // Use transient to ensure we only run once
        $sync_flag = get_transient('vietshield_threat_intel_syncing_initial');
        if ($sync_flag === 'done') {
            return; // Already synced
        }
        
        // Set flag immediately to prevent multiple runs
        set_transient('vietshield_threat_intel_syncing_initial', 'processing', 60);
        
        $options = get_option('vietshield_options', []);
        
        // Check if threat intel is enabled and category is set
        if (empty($options['threat_intel_enabled']) || empty($options['threat_intel_category'])) {
            delete_transient('vietshield_threat_intel_syncing_initial');
            return;
        }
        
        // Check if there's data in the table
        global $wpdb;
        $table = $wpdb->prefix . 'vietshield_threat_intel';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Safe table name
        $count = $wpdb->get_var("SELECT COUNT(*) FROM {$table}");
        
        if ($count > 0) {
            // Already has data, mark as done
            set_transient('vietshield_threat_intel_syncing_initial', 'done', 3600);
            return;
        }
        
        // Run sync immediately (don't wait)
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-threat-intelligence.php';
        $threat_intel = new \VietShield\Firewall\ThreatIntelligence();
        $result = $threat_intel->sync_feed($options['threat_intel_category']);
        
        // Clear any scheduled sync since we ran it directly
        wp_clear_scheduled_hook('vietshield_threat_intel_initial_sync');
        
        // Mark as done
        set_transient('vietshield_threat_intel_syncing_initial', 'done', 3600);
        
        // Log result for debugging
        if ($result && isset($result['success'])) {
            if ($result['success']) {
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
                error_log('VietShield: Threat Intelligence initial sync completed. IPs: ' . ($result['inserted'] ?? 0));
            } else {
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
                error_log('VietShield: Threat Intelligence initial sync failed: ' . ($result['error'] ?? 'Unknown error'));
            }
        } else {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
            error_log('VietShield: Threat Intelligence initial sync - no result returned');
        }
    }
    
    /**
     * Activation notice
     */
    public function activation_notice() {
        ?>
        <div class="notice notice-success is-dismissible">
            <p>
                <strong><?php esc_html_e('VietShield WAF has been activated!', 'vietshield-waf'); ?></strong>
                <?php esc_html_e('Your site is now protected. Visit the', 'vietshield-waf'); ?>
                <a href="<?php echo esc_url(admin_url('admin.php?page=vietshield-waf')); ?>">
                    <?php esc_html_e('dashboard', 'vietshield-waf'); ?>
                </a>
                <?php esc_html_e('to configure settings.', 'vietshield-waf'); ?>
            </p>
        </div>
        <?php
    }
    
    /**
     * AJAX: Get stats
     */
    public function ajax_get_stats() {
        check_ajax_referer('vietshield_admin', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }
        
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/logging/class-traffic-logger.php';
        $logger = new VietShield\Logging\TrafficLogger();
        
        $days = isset($_POST['days']) ? absint($_POST['days']) : 7;
        $stats = $logger->get_stats($days);
        
        wp_send_json_success($stats);
    }
    
    /**
     * AJAX: Get logs
     */
    public function ajax_get_logs() {
        check_ajax_referer('vietshield_admin', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }
        
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/logging/class-traffic-logger.php';
        $logger = new VietShield\Logging\TrafficLogger();
        
        $args = [
            'page' => isset($_POST['page']) ? absint($_POST['page']) : 1,
            'per_page' => isset($_POST['per_page']) ? absint($_POST['per_page']) : 50,
            'action' => isset($_POST['action_filter']) ? sanitize_text_field(wp_unslash($_POST['action_filter'])) : '',
            'attack_type' => isset($_POST['attack_type']) ? sanitize_text_field(wp_unslash($_POST['attack_type'])) : '',
            'ip' => isset($_POST['ip']) ? sanitize_text_field(wp_unslash($_POST['ip'])) : '',
            'block_id' => isset($_POST['block_id']) ? sanitize_text_field(wp_unslash($_POST['block_id'])) : '',
            'search' => isset($_POST['search']) ? sanitize_text_field(wp_unslash($_POST['search'])) : '',
        ];
        
        $logs = $logger->get_logs($args);
        
        wp_send_json_success($logs);
    }
    
    /**
     * AJAX: Get log details
     */
    public function ajax_get_log_details() {
        check_ajax_referer('vietshield_admin', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }
        
        $log_id = isset($_POST['log_id']) ? absint($_POST['log_id']) : 0;
        
        if (!$log_id) {
            wp_send_json_error('Invalid log ID');
        }
        
        global $wpdb;
        $table = $wpdb->prefix . 'vietshield_logs';
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Safe table name, value prepared
        $log = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$table} WHERE id = %d",
            $log_id
        ), ARRAY_A);
        
        if (!$log) {
            wp_send_json_error('Log not found');
        }
        
        // Format timestamp
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-vietshield-helpers.php';
        $log['formatted_timestamp'] = \VietShield_Helpers::format_timestamp($log['timestamp'], 'Y-m-d H:i:s');
        
        // Parse POST data if exists
        if (!empty($log['post_data']) && $log['post_data'] !== '[]' && trim($log['post_data']) !== '') {
            $parsed = json_decode($log['post_data'], true);
            // Only set if parsing succeeded and result is not null
            if ($parsed !== null) {
                $log['post_data_parsed'] = $parsed;
            }
        }
        
        // Check if IP is already blocked
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-ip-manager.php';
        $ip_manager = new \VietShield\Firewall\IPManager();
        $log['is_blocked'] = $ip_manager->is_blacklisted($log['ip']);
        
        wp_send_json_success($log);
    }

    /**
     * AJAX: Start file scan
     */
    public function ajax_start_file_scan() {
        check_ajax_referer('vietshield_admin', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        $options = get_option('vietshield_options', []);
        $enabled = $options['file_scanner_enabled'] ?? true;
        if (!$enabled) {
            wp_send_json_error('File scanner is disabled');
        }

        require_once VIETSHIELD_PLUGIN_DIR . 'includes/scanner/class-file-scanner.php';
        $scanner = new \VietShield\Scanner\FileScanner();
        $summary = $scanner->run_scan();

        wp_send_json_success($summary);
    }

    /**
     * AJAX: Get file scan results
     */
    public function ajax_get_file_scan() {
        check_ajax_referer('vietshield_admin', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        $scan_id = isset($_POST['scan_id']) ? absint($_POST['scan_id']) : 0;
        $page = isset($_POST['page']) ? absint($_POST['page']) : 1;
        $per_page = isset($_POST['per_page']) ? absint($_POST['per_page']) : 50;
        $status = isset($_POST['status']) ? sanitize_text_field(wp_unslash($_POST['status'])) : '';

        require_once VIETSHIELD_PLUGIN_DIR . 'includes/scanner/class-file-scanner.php';
        $scanner = new \VietShield\Scanner\FileScanner();

        if (!$scan_id) {
            $latest = $scanner->get_latest_scan();
            if (!$latest) {
                wp_send_json_success(['scan' => null, 'items' => [], 'total_items' => 0]);
            }
            $scan_id = (int) $latest['id'];
        }

        $result = $scanner->get_scan($scan_id, [
            'page' => $page,
            'per_page' => $per_page,
            'status' => $status,
        ]);

        if (!$result) {
            wp_send_json_error('Scan not found');
        }

        wp_send_json_success($result);
    }

    /**
     * Handle options update (reschedule file scan)
     */
    public function handle_options_update($old_value, $value) {
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/scanner/class-file-scanner.php';
        \VietShield\Scanner\FileScanner::reschedule($value);
        
        // Reschedule malware scanner
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/scanner/class-malware-scanner.php';
        \VietShield\Scanner\MalwareScanner::reschedule($value);
        
        // Reschedule threat intelligence sync if category changed
        $old_category = $old_value['threat_intel_category'] ?? '';
        $new_category = $value['threat_intel_category'] ?? '';
        
        if ($old_category !== $new_category) {
            require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-threat-intelligence.php';
            \VietShield\Firewall\ThreatIntelligence::schedule_sync($new_category);
        }
        
        // Auto-enable Whitelist Admins when WAF is enabled
        $old_waf_enabled = !empty($old_value['waf_enabled']);
        $new_waf_enabled = !empty($value['waf_enabled']);
        
        if ($new_waf_enabled && !$old_waf_enabled) {
            // WAF was just enabled, auto-enable whitelist_admins
            if (empty($value['whitelist_admins'])) {
                $value['whitelist_admins'] = true;
            }
        }
        
        // Handle firewall mode changes
        $old_mode = $old_value['firewall_mode'] ?? 'protecting';
        $new_mode = $value['firewall_mode'] ?? 'protecting';
        // Backward compatibility: map old values to new
        if ($old_mode === 'extended') {
            $old_mode = 'protecting';
        }
        if ($new_mode === 'extended') {
            $new_mode = 'protecting';
        }
        
        // Auto-enable/disable early blocking based on firewall mode
        $needs_update = false;
        if ($new_mode === 'extended') {
            if (empty($value['early_blocking_enabled'])) {
                $value['early_blocking_enabled'] = true;
                $needs_update = true;
            }
        } else {
            if (!empty($value['early_blocking_enabled'])) {
                $value['early_blocking_enabled'] = false;
                $needs_update = true;
            }
        }
        
        // Only update if early_blocking_enabled changed to avoid infinite loop
        if ($needs_update) {
            // Remove hook temporarily to prevent infinite loop
            remove_action('update_option_vietshield_options', [$this, 'handle_options_update'], 10);
            update_option('vietshield_options', $value);
            // Re-add hook
            add_action('update_option_vietshield_options', [$this, 'handle_options_update'], 10, 2);
        }
        
        // Sync early blocker
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-early-blocker.php';
        $early_blocker = new \VietShield\Firewall\EarlyBlocker();
        
        if ($new_mode === 'protecting') {
            $early_blocker->sync_blocked_ips();
        } else {
            $early_blocker->disable();
        }
        
        // Trigger IP whitelist sync if Googlebot option was just enabled
        $old_googlebot = !empty($old_value['whitelist_googlebot']);
        $new_googlebot = !empty($value['whitelist_googlebot']);
        
        if ($new_googlebot && !$old_googlebot) {
            // Schedule immediate sync
            if (!wp_next_scheduled('vietshield_ip_whitelist_sync')) {
                wp_schedule_single_event(time() + 5, 'vietshield_ip_whitelist_sync');
            }
        }
    }

    /**
     * AJAX: Start malware scan
     */
    public function ajax_start_malware_scan() {
        check_ajax_referer('vietshield_admin', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        $options = get_option('vietshield_options', []);
        $enabled = $options['malware_scanner_enabled'] ?? true;
        if (!$enabled) {
            wp_send_json_error('Malware scanner is disabled');
        }

        $scope = isset($_POST['scope']) ? sanitize_text_field(wp_unslash($_POST['scope'])) : 'all';
        $allowed_scopes = ['all', 'themes', 'plugins', 'uploads', 'mu-plugins'];
        if (!in_array($scope, $allowed_scopes, true)) {
            $scope = 'all';
        }

        require_once VIETSHIELD_PLUGIN_DIR . 'includes/scanner/class-malware-scanner.php';
        $scanner = new \VietShield\Scanner\MalwareScanner();
        $summary = $scanner->run_scan($scope);

        wp_send_json_success($summary);
    }

    /**
     * AJAX: Get malware scan results
     */
    public function ajax_get_malware_scan() {
        check_ajax_referer('vietshield_admin', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        $scan_id = isset($_POST['scan_id']) ? absint($_POST['scan_id']) : 0;
        $page = isset($_POST['page']) ? absint($_POST['page']) : 1;
        $per_page = isset($_POST['per_page']) ? absint($_POST['per_page']) : 50;
        $severity = isset($_POST['severity']) ? sanitize_text_field(wp_unslash($_POST['severity'])) : '';

        require_once VIETSHIELD_PLUGIN_DIR . 'includes/scanner/class-malware-scanner.php';
        $scanner = new \VietShield\Scanner\MalwareScanner();

        if (!$scan_id) {
            $latest = $scanner->get_latest_scan();
            if (!$latest) {
                wp_send_json_success(['scan' => null, 'items' => [], 'total_items' => 0]);
            }
            $scan_id = (int) $latest['id'];
        }

        $result = $scanner->get_scan($scan_id, [
            'page' => $page,
            'per_page' => $per_page,
            'severity' => $severity,
        ]);

        if (!$result) {
            wp_send_json_error('Scan not found');
        }

        wp_send_json_success($result);
    }

    /**
     * AJAX: Clear malware scan history
     */
    public function ajax_clear_malware_history() {
        check_ajax_referer('vietshield_admin', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
        $wpdb->query('TRUNCATE TABLE ' . $wpdb->prefix . 'vietshield_malware_scan_items');
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
        $wpdb->query('TRUNCATE TABLE ' . $wpdb->prefix . 'vietshield_malware_scans');

        wp_send_json_success(['message' => 'Malware scan history cleared successfully']);
    }

    /**
     * AJAX: Clear file scan history
     */
    public function ajax_clear_file_history() {
        check_ajax_referer('vietshield_admin', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
        $wpdb->query('TRUNCATE TABLE ' . $wpdb->prefix . 'vietshield_file_scan_items');
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
        $wpdb->query('TRUNCATE TABLE ' . $wpdb->prefix . 'vietshield_file_scans');

        wp_send_json_success(['message' => 'File scan history cleared successfully']);
    }
    
    /**
     * AJAX: Sync threat intelligence feed
     */
    public function ajax_sync_threat_intel() {
        check_ajax_referer('vietshield_admin', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        $category = isset($_POST['category']) ? sanitize_text_field(wp_unslash($_POST['category'])) : '';
        $allowed_categories = ['1d', '3d', '7d', '14d', '30d'];
        
        if (!in_array($category, $allowed_categories, true)) {
            wp_send_json_error('Invalid category');
        }

        // Set syncing flag
        set_transient('vietshield_threat_intel_syncing', true, 600); // 10 minutes timeout

        try {
            // Increase execution time for large feeds
            // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged -- Required for large threat intel sync
            @set_time_limit(600); // 10 minutes
            // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged -- Required for large threat intel sync
            @ini_set('max_execution_time', 600);
            
            require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-threat-intelligence.php';
            $threat_intel = new \VietShield\Firewall\ThreatIntelligence();
            
            $result = $threat_intel->sync_feed($category);

            // Clear syncing flag
            delete_transient('vietshield_threat_intel_syncing');

            if ($result['success']) {
                // Update category in options
                $options = get_option('vietshield_options', []);
                $options['threat_intel_category'] = $category;
                update_option('vietshield_options', $options);
                
                // Reschedule automatic sync
                \VietShield\Firewall\ThreatIntelligence::schedule_sync($category);

                wp_send_json_success([
                    'message' => sprintf('Successfully synced %s IPs from %s feed.', number_format($result['inserted']), strtoupper($category)),
                    'count' => $result['inserted'],
                    'category' => $category,
                ]);
            } else {
                wp_send_json_error([
                    'message' => $result['error'] ?? 'Failed to sync feed',
                    'details' => $result,
                ]);
            }
        } catch (\Exception $e) {
            delete_transient('vietshield_threat_intel_syncing');
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
            error_log('VietShield Threat Intel Sync Error: ' . $e->getMessage());
            wp_send_json_error([
                'message' => 'Sync failed: ' . $e->getMessage(),
            ]);
        }
    }

    /**
     * AJAX: Clear threat intelligence data
     */
    public function ajax_clear_threat_intel() {
        check_ajax_referer('vietshield_admin', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-threat-intelligence.php';
        $threat_intel = new \VietShield\Firewall\ThreatIntelligence();
        
        $threat_intel->clear_data();

        // Clear category from options
        $options = get_option('vietshield_options', []);
        $options['threat_intel_category'] = '';
        update_option('vietshield_options', $options);
        
        // Clear scheduled sync
        \VietShield\Firewall\ThreatIntelligence::schedule_sync('');

        wp_send_json_success(['message' => 'Threat intelligence data cleared successfully']);
    }

    /**
     * AJAX: Get threat intelligence status
     */
    public function ajax_get_threat_intel_status() {
        check_ajax_referer('vietshield_admin', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-threat-intelligence.php';
        $threat_intel = new \VietShield\Firewall\ThreatIntelligence();
        
        $status = $threat_intel->get_sync_status();

        wp_send_json_success($status);
    }

    /**
     * AJAX: Sync early blocker
     */
    public function ajax_sync_early_blocker() {
        check_ajax_referer('vietshield_admin', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-early-blocker.php';
        $early_blocker = new \VietShield\Firewall\EarlyBlocker();
        
        $result = $early_blocker->sync_blocked_ips();
        
        if (is_array($result) && !empty($result['success'])) {
            $stats = $early_blocker->get_stats();
            wp_send_json_success([
                'message' => $result['message'] ?? 'Early blocker synced successfully',
                'stats' => $stats,
                'total_ips' => $result['total_ips'] ?? 0,
            ]);
        } else {
            $error_message = is_array($result) && isset($result['message']) 
                ? $result['message'] 
                : 'Failed to sync early blocker. Please check error logs for details.';
            wp_send_json_error($error_message);
        }
    }
    
    /**
     * AJAX: Block IP
     */
    public function ajax_block_ip() {
        check_ajax_referer('vietshield_admin', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }
        
        $ip = isset($_POST['ip']) ? sanitize_text_field(wp_unslash($_POST['ip'])) : '';
        $reason = isset($_POST['reason']) ? sanitize_text_field(wp_unslash($_POST['reason'])) : 'Manually blocked';
        $duration = isset($_POST['duration']) ? absint($_POST['duration']) : 0;
        
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            wp_send_json_error('Invalid IP address');
        }
        
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-ip-manager.php';
        $ip_manager = new VietShield\Firewall\IPManager();
        
        $type = $duration > 0 ? 'temporary' : 'blacklist';
        $result = $ip_manager->add_to_blacklist($ip, $type, $reason, $duration);
        
        if ($result) {
            // Sync early blocker
            require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-early-blocker.php';
            $early_blocker = new \VietShield\Firewall\EarlyBlocker();
            $early_blocker->sync_blocked_ips();
            
            wp_send_json_success(['message' => 'IP blocked successfully']);
        } else {
            wp_send_json_error('Failed to block IP');
        }
    }
    
    /**
     * AJAX: Unblock IP
     */
    public function ajax_unblock_ip() {
        check_ajax_referer('vietshield_admin', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }
        
        $ip = isset($_POST['ip']) ? sanitize_text_field(wp_unslash($_POST['ip'])) : '';
        
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-ip-manager.php';
        $ip_manager = new VietShield\Firewall\IPManager();
        
        $ip_manager->remove_ip($ip);
        
        // Sync early blocker
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-early-blocker.php';
        $early_blocker = new \VietShield\Firewall\EarlyBlocker();
        $early_blocker->sync_blocked_ips();
        
        wp_send_json_success(['message' => 'IP unblocked successfully']);
    }
    
    /**
     * AJAX: Clear logs
     */
    public function ajax_clear_logs() {
        check_ajax_referer('vietshield_admin', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }
        
        global $wpdb;
        $table = $wpdb->prefix . 'vietshield_logs';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Admin log clear
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
        $wpdb->query("TRUNCATE TABLE $table");
        
        wp_send_json_success(['message' => 'Logs cleared successfully']);
    }
    
    /**
     * AJAX: Sync IP Whitelist (Googlebot/Cloudflare)
     */
    public function ajax_sync_ip_whitelist() {
        check_ajax_referer('vietshield_admin', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }
        
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-ip-whitelist-sync.php';
        $results = \VietShield\Firewall\IPWhitelistSync::sync_all();
        $status = \VietShield\Firewall\IPWhitelistSync::get_sync_status();
        
        wp_send_json_success([
            'message' => 'IP whitelist synced successfully',
            'results' => $results,
            'status' => $status,
        ]);
    }
}
