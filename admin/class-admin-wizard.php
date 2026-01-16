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
        $current_page = $_GET['page'] ?? '';
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
        $pagenow = $GLOBALS['pagenow'] ?? basename($_SERVER['PHP_SELF']);
        if ($pagenow === 'admin-post.php' || $pagenow === 'admin-ajax.php') {
            return;
        }
        
        // Check if wizard should be shown
        $wizard_completed = get_option('vietshield_wizard_completed', false);
        
        if (!$wizard_completed) {
            // Get current page info
            $current_page = $_GET['page'] ?? '';
            $is_wizard_page = ($current_page === 'vietshield-wizard');
            $is_settings_page = ($current_page === 'vietshield-settings');
            $is_plugins_page = ($pagenow === 'plugins.php');
            $is_activation = (isset($_GET['activate']) && $_GET['activate'] === 'true');
            
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
        $current_step = isset($_GET['step']) ? intval($_GET['step']) : 1;
        $webserver = $this->detect_webserver();
        
        include VIETSHIELD_PLUGIN_DIR . 'admin/views/wizard.php';
    }
    
    /**
     * Detect webserver type
     */
    public function detect_webserver() {
        $server_software = $_SERVER['SERVER_SOFTWARE'] ?? '';
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
        check_ajax_referer('vietshield_wizard', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied', 'vietshield-waf')]);
        }
        
        $step = isset($_POST['step']) ? intval($_POST['step']) : 0;
        $data = isset($_POST['data']) ? $_POST['data'] : [];
        
        // Save step data
        update_option('vietshield_wizard_step_' . $step, $data);
        
        wp_send_json_success(['message' => __('Step saved', 'vietshield-waf')]);
    }
    
    /**
     * AJAX: Complete wizard
     */
    public function ajax_complete_wizard() {
        check_ajax_referer('vietshield_wizard', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied', 'vietshield-waf')]);
        }
        
        $data = isset($_POST['data']) ? $_POST['data'] : [];
        
        // Get all wizard steps data
        $wizard_data = [];
        for ($i = 1; $i <= 3; $i++) {
            $step_data = get_option('vietshield_wizard_step_' . $i, []);
            if (!empty($step_data)) {
                $wizard_data = array_merge($wizard_data, $step_data);
            }
        }
        
        // Merge with final step data
        $wizard_data = array_merge($wizard_data, $data);
        
        // Apply wizard settings
        $this->apply_wizard_settings($wizard_data);
        
        // Mark wizard as completed
        update_option('vietshield_wizard_completed', true);
        delete_transient('vietshield_show_wizard');
        
        // Clean up step data
        for ($i = 1; $i <= 3; $i++) {
            delete_option('vietshield_wizard_step_' . $i);
        }
        
        wp_send_json_success([
            'message' => __('Wizard completed successfully!', 'vietshield-waf'),
            'redirect' => admin_url('admin.php?page=vietshield-waf')
        ]);
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
        
        // If protecting mode, enable early blocking
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
            $options['block_rce'] = true;
            $options['block_lfi'] = true;
            $options['block_bad_bots'] = true;
        }
        
        // Early blocking settings - enable if protecting mode
        if ($firewall_mode === 'protecting') {
            require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-early-blocker.php';
            $early_blocker = new \VietShield\Firewall\EarlyBlocker();
            $early_blocker->enable();
        }
        
        // Save options
        update_option('vietshield_options', $options);
        
        // Sync early blocker if enabled
        if (!empty($options['early_blocking_enabled'])) {
            require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-early-blocker.php';
            $early_blocker = new \VietShield\Firewall\EarlyBlocker();
            $early_blocker->sync_blocked_ips();
        }
    }
}
