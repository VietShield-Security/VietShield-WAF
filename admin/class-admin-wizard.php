<?php
/**
 * Setup Wizard for first-time installation
 * 
 * @package VietShield_WAF
 */

if (!defined('ABSPATH')) {
    exit;
}

class VietShield_Admin_Wizard {
    
    /**
     * Constructor
     */
    public function __construct() {
        // Use admin_init with priority 1 to run early
        add_action('admin_init', [$this, 'check_wizard'], 1);
        add_action('admin_menu', [$this, 'add_wizard_page']);
        add_action('wp_ajax_vietshield_wizard_save', [$this, 'ajax_save_step']);
        add_action('wp_ajax_vietshield_wizard_complete', [$this, 'ajax_complete_wizard']);
        
        // Fix PHP 8.x null title warning - set title early in admin_init
        add_action('admin_init', [$this, 'fix_wizard_title'], 0);
    }
    
    /**
     * Fix title for wizard page early (PHP 8.x compatibility)
     * This runs before admin-header.php calls strip_tags($title)
     */
    public function fix_wizard_title() {
        global $title, $pagenow;
        
        // Check if we're on the wizard page
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Just reading page name for title
        $current_page = isset($_GET['page']) ? sanitize_text_field(wp_unslash($_GET['page'])) : '';
        if ($current_page === 'vietshield-wizard' && empty($title)) {
            $title = __('Setup Wizard', 'vietshield-waf');
        }
    }
    
    /**
     * Check if wizard should be shown
     */
    public function check_wizard() {
        // Only show to admins
        if (!current_user_can('manage_options')) {
            return;
        }
        
        // Don't redirect on AJAX requests
        if (defined('DOING_AJAX') && DOING_AJAX) {
            return;
        }
        
        // Don't redirect on cron requests
        if (defined('DOING_CRON') && DOING_CRON) {
            return;
        }
        
        // Don't redirect on admin-post requests
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Just for page name comparison
        $pagenow = $GLOBALS['pagenow'] ?? (isset($_SERVER['PHP_SELF']) ? basename(sanitize_text_field(wp_unslash($_SERVER['PHP_SELF']))) : '');
        if ($pagenow === 'admin-post.php' || $pagenow === 'admin-ajax.php') {
            return;
        }
        
        // Check if wizard should be shown
        $wizard_completed = get_option('vietshield_wizard_completed', false);
        
        if (!$wizard_completed) {
            // Get current page info
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Just reading page name for redirect
            $current_page = isset($_GET['page']) ? sanitize_text_field(wp_unslash($_GET['page'])) : '';
            $is_wizard_page = ($current_page === 'vietshield-wizard');
            $is_settings_page = ($current_page === 'vietshield-settings');
            $is_plugins_page = ($pagenow === 'plugins.php');
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Just checking activation state
            $is_activation = (isset($_GET['activate']) && sanitize_text_field(wp_unslash($_GET['activate'])) === 'true');
            
            // Always redirect to wizard if:
            // 1. Not already on wizard page
            // 2. On settings page (should redirect to wizard)
            // 3. Not during activation process on plugins page
            if (!$is_wizard_page) {
                // Allow plugins page to finish activation
                if ($is_plugins_page && $is_activation) {
                    return;
                }
                
                // Redirect to wizard
                wp_safe_redirect(admin_url('admin.php?page=vietshield-wizard'));
                exit;
            }
        }
    }
    
    /**
     * Add wizard page
     */
    public function add_wizard_page() {
        // Use 'options.php' as parent - this is a valid WordPress admin page that exists
        // but won't show in menu. This fixes PHP 8.x null title issue.
        add_submenu_page(
            'options.php', // Hidden but valid parent page
            __('Setup Wizard', 'vietshield-waf'),
            __('Setup Wizard', 'vietshield-waf'),
            'manage_options',
            'vietshield-wizard',
            [$this, 'render_wizard']
        );
    }
    
    /**
     * Render wizard page
     */
    public function render_wizard() {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Just reading step number for display
        $current_step = isset($_GET['step']) ? intval($_GET['step']) : 1;
        $webserver = $this->detect_webserver();
        
        include VIETSHIELD_PLUGIN_DIR . 'admin/views/wizard.php';
    }
    
    /**
     * Detect webserver type
     */
    public function detect_webserver() {
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Server software string for detection
        $server_software = isset($_SERVER['SERVER_SOFTWARE']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE'])) : '';
        $server_software = strtolower($server_software);
        
        // Check for Apache
        if (strpos($server_software, 'apache') !== false) {
            // Check if PHP-FPM
            if (function_exists('fastcgi_finish_request') || strpos(php_sapi_name(), 'fpm') !== false) {
                return 'apache-fpm';
            }
            return 'apache';
        }
        
        // Check for Nginx
        if (strpos($server_software, 'nginx') !== false) {
            return 'nginx';
        }
        
        // Check PHP-FPM
        if (strpos(php_sapi_name(), 'fpm') !== false) {
            return 'php-fpm';
        }
        
        // Default to Apache
        return 'apache';
    }
    
    /**
     * Get webserver configuration method
     */
    public function get_webserver_config_method($webserver) {
        switch ($webserver) {
            case 'apache':
                return '.htaccess';
            case 'apache-fpm':
            case 'nginx':
            case 'php-fpm':
                return '.user.ini';
            default:
                return '.htaccess';
        }
    }
    
    /**
     * AJAX: Save wizard step
     */
    public function ajax_save_step() {
        check_ajax_referer('vietshield_admin', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied', 'vietshield-waf')]);
        }
        
        $step = isset($_POST['step']) ? intval($_POST['step']) : 0;
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Array data, sanitized when used
        $data = isset($_POST['data']) ? map_deep(wp_unslash($_POST['data']), 'sanitize_text_field') : [];
        
        // Save step data
        update_option('vietshield_wizard_step_' . $step, $data);
        
        wp_send_json_success(['message' => __('Step saved', 'vietshield-waf')]);
    }
    
    /**
     * AJAX: Complete wizard - simplified single call
     * Saves settings and schedules syncs for background execution
     */
    public function ajax_complete_wizard() {
        // Try both nonce field names for compatibility
        $nonce = '';
        if (isset($_POST['nonce'])) {
            $nonce = sanitize_text_field(wp_unslash($_POST['nonce']));
        } elseif (isset($_POST['_ajax_nonce'])) {
            $nonce = sanitize_text_field(wp_unslash($_POST['_ajax_nonce']));
        } elseif (isset($_POST['security'])) {
            $nonce = sanitize_text_field(wp_unslash($_POST['security']));
        }
        
        // Verify nonce - try multiple action names for compatibility
        $nonce_valid = false;
        if (!empty($nonce)) {
            if (wp_verify_nonce($nonce, 'vietshield_admin')) {
                $nonce_valid = true;
            } elseif (wp_verify_nonce($nonce, 'vietshield_wizard')) {
                $nonce_valid = true;
            } elseif (wp_verify_nonce($nonce, 'vietshield-admin-nonce')) {
                $nonce_valid = true;
            }
        }
        
        if (!$nonce_valid) {
            wp_send_json_error([
                'message' => __('Security verification failed. Please refresh the page and try again.', 'vietshield-waf'),
                'error_code' => 'nonce_failed'
            ]);
            return;
        }
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied', 'vietshield-waf')]);
            return;
        }
        
        // Get wizard data
        $wizard_data = [
            'firewall_mode' => isset($_POST['firewall_mode']) ? sanitize_text_field(wp_unslash($_POST['firewall_mode'])) : 'protecting',
            'auto_optimize' => isset($_POST['auto_optimize']) ? (bool) $_POST['auto_optimize'] : true,
        ];
        
        // Ensure VIETSHIELD_PLUGIN_DIR is defined
        if (!defined('VIETSHIELD_PLUGIN_DIR')) {
            define('VIETSHIELD_PLUGIN_DIR', plugin_dir_path(dirname(__FILE__)));
        }
        
        try {
            // Apply wizard settings
            $this->apply_wizard_settings($wizard_data);
            
            // Mark wizard as completed
            update_option('vietshield_wizard_completed', true);
            delete_transient('vietshield_show_wizard');
            delete_option('vietshield_wizard_in_progress');
            
            // Clean up old step data
            for ($i = 1; $i <= 3; $i++) {
                delete_option('vietshield_wizard_step_' . $i);
            }
            
            // Ensure IP lists table exists (for Googlebot whitelist)
            $this->ensure_ip_lists_table();
            
            // Ensure threat intel table exists
            $this->ensure_threat_intel_table();
            
            // Get options for sync decisions
            $options = get_option('vietshield_options', []);
            
            // Run Googlebot sync DIRECTLY (not via cron) to ensure it completes
            if (!empty($options['whitelist_googlebot'])) {
                require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-ip-whitelist-sync.php';
                $sync_result = \VietShield\Firewall\IPWhitelistSync::sync_googlebot();
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
                error_log('VietShield Wizard: Googlebot sync result: ' . wp_json_encode($sync_result));
            }
            
            // Schedule Threat Intelligence sync for background (can be slow)
            if (!empty($options['threat_intel_enabled']) && !empty($options['threat_intel_category'])) {
                wp_schedule_single_event(time(), 'vietshield_threat_intel_initial_sync');
            }
            
            // Setup Early Blocker directly
            if (!empty($options['early_blocking_enabled']) && $wizard_data['firewall_mode'] === 'protecting') {
                require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-early-blocker.php';
                $early_blocker = new \VietShield\Firewall\EarlyBlocker();
                $early_blocker->enable();
                $early_blocker->sync_blocked_ips();
            }
            
            // Trigger cron to run threat intel sync (non-blocking)
            spawn_cron();
            
            // Return success
            wp_send_json_success([
                'message' => __('Protection activated! Syncing data in background...', 'vietshield-waf'),
                'firewall_mode' => $wizard_data['firewall_mode']
            ]);
            
        } catch (\Exception $e) {
            wp_send_json_error([
                'message' => $e->getMessage(),
                'error' => $e->getMessage()
            ]);
        } catch (\Error $e) {
            wp_send_json_error([
                'message' => $e->getMessage(),
                'error' => $e->getMessage()
            ]);
        }
    }
    
    /**
     * Ensure IP lists table exists
     */
    private function ensure_ip_lists_table() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'vietshield_ip_lists';
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $table_exists = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table_name));
        
        if ($table_exists !== $table_name) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
            error_log("VietShield Wizard: Creating ip_lists table");
            
            $charset_collate = $wpdb->get_charset_collate();
            
            $sql = "CREATE TABLE {$table_name} (
                id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                ip_address varchar(45) NOT NULL,
                list_type enum('whitelist','blocklist') NOT NULL DEFAULT 'blocklist',
                reason varchar(255) DEFAULT NULL,
                created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
                expires_at datetime DEFAULT NULL,
                hit_count int(11) NOT NULL DEFAULT 0,
                PRIMARY KEY (id),
                KEY ip_address (ip_address),
                KEY list_type (list_type)
            ) {$charset_collate};";
            
            require_once ABSPATH . 'wp-admin/includes/upgrade.php';
            dbDelta($sql);
        }
    }
    
    /**
     * Ensure threat intelligence table exists
     */
    private function ensure_threat_intel_table() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'vietshield_threat_intel';
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $table_exists = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table_name));
        
        if ($table_exists !== $table_name) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
            error_log("VietShield Wizard: Creating threat_intel table");
            
            $charset_collate = $wpdb->get_charset_collate();
            
            $sql = "CREATE TABLE {$table_name} (
                id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                ip_address varchar(45) NOT NULL,
                category varchar(50) NOT NULL,
                source varchar(100) DEFAULT NULL,
                last_seen datetime DEFAULT NULL,
                created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (id),
                UNIQUE KEY ip_category (ip_address, category),
                KEY category (category)
            ) {$charset_collate};";
            
            require_once ABSPATH . 'wp-admin/includes/upgrade.php';
            dbDelta($sql);
        }
    }
    
    /**
     * Apply wizard settings to options
     */
    private function apply_wizard_settings($data) {
        $options = get_option('vietshield_options', []);
        
        // WAF is always enabled when completing wizard
        $options['waf_enabled'] = true;
        
        // Firewall mode (default to protecting if not set)
        $firewall_mode = isset($data['firewall_mode']) ? sanitize_text_field($data['firewall_mode']) : 'protecting';
        // Map old values to new values for backward compatibility
        if ($firewall_mode === 'extended') {
            $firewall_mode = 'protecting';
        }
        $options['firewall_mode'] = $firewall_mode;
        
        // If protecting mode, enable early blocking (but don't activate yet - let early_blocker step do it)
        if ($firewall_mode === 'protecting') {
            $options['early_blocking_enabled'] = true;
        } else {
            $options['early_blocking_enabled'] = false;
        }
        
        // Web server configuration
        if (isset($data['webserver'])) {
            $options['webserver_type'] = sanitize_text_field($data['webserver']);
        }
        
        // Auto-optimize settings
        if (isset($data['auto_optimize']) && $data['auto_optimize']) {
            // Enable all recommended features
            $options['login_security_enabled'] = true;
            $options['threat_intel_enabled'] = true;
            $options['threat_intel_category'] = '1d'; // 1 day threat intelligence
            $options['rate_limiting_enabled'] = true;
            $options['country_blocking_enabled'] = true; // Enabled as per wizard list
            $options['block_unknown_countries'] = false; // Don't block unknown by default to be safe
            $options['file_scanner_enabled'] = true;
            $options['malware_scanner_enabled'] = true;
            
            // Default IP Whitelist settings (Googlebot)
            $options['whitelist_googlebot'] = true;

            // Enable protection features
            $options['block_sqli'] = true;
            $options['block_xss'] = true;
            $options['block_rce'] = false; // Default OFF - RCE detection may cause false positives
            $options['block_lfi'] = true;
            $options['block_bad_bots'] = true;
        }
        
        // Auto-detect Cloudflare usage
        // If the site is behind Cloudflare, these headers should be present
        if (!empty($_SERVER['HTTP_CF_RAY']) || !empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $options['cloudflare_enabled'] = true;
            // Also enable trusted proxies if not already set (will be populated by sync)
            if (empty($options['trusted_proxies'])) {
                $options['trusted_proxies'] = [];
            }
        }
        
        // IMPORTANT: Do NOT enable early blocking here!
        // The early_blocker step (last step) will handle enabling and syncing.
        // If we enable it here, subsequent AJAX requests (googlebot, cloudflare, etc.)
        // might be blocked before they can complete.
        
        // Save options (but don't trigger sync hooks during wizard)
        // We'll use a flag to prevent sync during wizard
        update_option('vietshield_wizard_in_progress', true);
        update_option('vietshield_options', $options);
    }
    
    /**
     * Regenerate early blocker file from template
     * Forces update of vietshield-blocker.php with admin-ajax.php bypass
     */
    private function regenerate_early_blocker() {
        $template_file = VIETSHIELD_PLUGIN_DIR . 'templates/early-blocker.php.tpl';
        $blocker_file = WP_CONTENT_DIR . '/vietshield-blocker.php';
        
        if (!file_exists($template_file)) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
            error_log("VietShield Wizard: Early blocker template not found: {$template_file}");
            return false;
        }
        
        // Always regenerate to ensure latest template with admin-ajax bypass
        $template_content = file_get_contents($template_file);
        
        if (empty($template_content)) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
            error_log("VietShield Wizard: Empty template content");
            return false;
        }
        
        // Write the blocker file
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Performance critical
        $result = file_put_contents($blocker_file, $template_content, LOCK_EX);
        
        if ($result !== false) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Performance critical
            @chmod($blocker_file, 0644);
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
            error_log("VietShield Wizard: Regenerated blocker file with admin-ajax bypass");
            return true;
        }
        
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
        error_log("VietShield Wizard: Failed to regenerate blocker file");
        return false;
    }
}
