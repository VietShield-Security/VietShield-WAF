<?php
/**
 * Plugin Activator
 * 
 * @package VietShield_WAF
 */

if (!defined('ABSPATH')) {
    exit;
}

class VietShield_Activator {
    
    /**
     * Activation tasks
     */
    public static function activate() {
        self::create_tables();
        self::add_missing_columns(); // Add new columns if missing
        self::set_default_options();
        self::create_rules_files();
        self::create_early_blocker_files();
        self::schedule_cron_jobs();
        
        // Flush rewrite rules
        flush_rewrite_rules();
        
        // Set activation flag and wizard flag for first-time install
        $is_first_install = !get_option('vietshield_wizard_completed', false);
        set_transient('vietshield_activated', true, 30);
        
        if ($is_first_install) {
            // Set wizard flag with longer expiry (24 hours) to ensure it shows
            set_transient('vietshield_show_wizard', true, 86400); // 24 hours
            // Also set option flag to ensure wizard shows
            if (!get_option('vietshield_wizard_completed', false)) {
                // Force redirect on next admin page load
                set_transient('vietshield_force_wizard_redirect', true, 86400); // 24 hours
                // Additional flag to ensure wizard loads
                set_transient('vietshield_wizard_should_load', true, 86400); // 24 hours
            }
        }
    }
    
    /**
     * Whitelist current admin IP immediately after activation
     */
    private static function whitelist_current_admin_ip() {
        // Get current user IP
        $ip = self::get_client_ip();
        
        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return;
        }
        
        // Skip private/local IPs
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return;
        }
        
        // Check if user is admin
        if (function_exists('is_user_logged_in') && is_user_logged_in()) {
            if (function_exists('current_user_can') && current_user_can('manage_options')) {
                // Add to whitelist
                require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-ip-manager.php';
                $ip_manager = new \VietShield\Firewall\IPManager();
                
                // Check if already whitelisted
                if (!$ip_manager->is_whitelisted($ip)) {
                    $ip_manager->add_to_whitelist($ip, 'Admin IP whitelisted on plugin activation');
                }
            }
        }
    }
    
    /**
     * Get client IP address
     */
    private static function get_client_ip() {
        $ip = '';
        
        // Check Cloudflare
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- IP address validation below
            $ip = sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_CONNECTING_IP']));
        }
        // Check X-Real-IP (Nginx)
        elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- IP address validation below
            $ip = sanitize_text_field(wp_unslash($_SERVER['HTTP_X_REAL_IP']));
        }
        // Check X-Forwarded-For
        elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- IP address validation below
            $ips = explode(',', sanitize_text_field(wp_unslash($_SERVER['HTTP_X_FORWARDED_FOR'])));
            $ip = trim($ips[0]);
        }
        // Default to REMOTE_ADDR
        else {
            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- IP address validation below
            $ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
        }
        
        return $ip;
    }
    
    /**
     * Auto-sync threat intelligence on first activation
     * This method is kept for backward compatibility but sync is now handled via cron hook
     */
    private static function auto_sync_threat_intel() {
        // Sync is now handled via wp_schedule_single_event in set_default_options()
        // This method is kept for reference
    }
    
    /**
     * Add missing columns to existing tables
     */
    private static function add_missing_columns() {
        global $wpdb;
        
        $table_logs = $wpdb->prefix . 'vietshield_logs';
        
        // Check if table exists
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Schema check
        if ($wpdb->get_var("SHOW TABLES LIKE '$table_logs'") !== $table_logs) {
            return; // Table doesn't exist, will be created by create_tables()
        }
        
        // Check and add country_code column
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Schema check
        $column_exists = $wpdb->get_results("SHOW COLUMNS FROM `$table_logs` LIKE 'country_code'");
        if (empty($column_exists)) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Schema migration
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
            $wpdb->query("ALTER TABLE `$table_logs` ADD COLUMN `country_code` VARCHAR(2) DEFAULT '' AFTER `country`");
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Schema migration
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
            $wpdb->query("ALTER TABLE `$table_logs` ADD INDEX `idx_country_code` (`country_code`)");
        }
        
        // Check and add as_number column
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Schema check
        $column_exists = $wpdb->get_results("SHOW COLUMNS FROM `$table_logs` LIKE 'as_number'");
        if (empty($column_exists)) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Schema migration
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
            $wpdb->query("ALTER TABLE `$table_logs` ADD COLUMN `as_number` VARCHAR(20) DEFAULT '' AFTER `country_code`");
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Schema migration
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
            $wpdb->query("ALTER TABLE `$table_logs` ADD INDEX `idx_as_number` (`as_number`)");
        }
        
        // Check and add as_name column
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Schema check
        $column_exists = $wpdb->get_results("SHOW COLUMNS FROM `$table_logs` LIKE 'as_name'");
        if (empty($column_exists)) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Schema migration
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
            $wpdb->query("ALTER TABLE `$table_logs` ADD COLUMN `as_name` VARCHAR(255) DEFAULT '' AFTER `as_number`");
        }
    }

    /**
     * Upgrade tasks (schema/options only)
     */
    public static function maybe_upgrade() {
        self::create_tables();
        self::add_missing_columns(); // Add new columns if missing
        self::upgrade_indexes(); // Add missing indexes to existing tables
        self::set_default_options();
        self::schedule_cron_jobs();
        update_option('vietshield_db_version', VIETSHIELD_DB_VERSION);
    }
    
    /**
     * Upgrade indexes for existing tables
     * Adds missing composite indexes for better query performance
     */
    private static function upgrade_indexes() {
        global $wpdb;
        
        $charset_collate = $wpdb->get_charset_collate();
        
        // Get list of tables
        $tables = [
            'logs' => $wpdb->prefix . 'vietshield_logs',
            'ip_lists' => $wpdb->prefix . 'vietshield_ip_lists',
            'login_attempts' => $wpdb->prefix . 'vietshield_login_attempts',
            'file_scan_items' => $wpdb->prefix . 'vietshield_file_scan_items',
            'malware_scan_items' => $wpdb->prefix . 'vietshield_malware_scan_items',
        ];
        
        // Check if tables exist and add missing indexes
        foreach ($tables as $table_key => $table_name) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Schema check
            if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") === $table_name) {
                self::add_missing_indexes($table_name, $table_key);
            }
        }
    }
    
    /**
     * Add missing indexes to a specific table
     */
    private static function add_missing_indexes($table_name, $table_key) {
        global $wpdb;
        
        // Get existing indexes (Key_name column from SHOW INDEXES)
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Schema introspection
        $existing_indexes_result = $wpdb->get_results("SHOW INDEXES FROM `$table_name`", ARRAY_A);
        $existing_indexes = [];
        foreach ($existing_indexes_result as $row) {
            $existing_indexes[] = $row['Key_name'];
        }
        $existing_indexes = array_unique($existing_indexes);
        
        $indexes_to_add = [];
        
        switch ($table_key) {
            case 'logs':
                $indexes_to_add = [
                    'idx_user_id' => 'ADD INDEX idx_user_id (user_id)',
                    'idx_country' => 'ADD INDEX idx_country (country)',
                    'idx_ip_timestamp' => 'ADD INDEX idx_ip_timestamp (ip, timestamp)',
                    'idx_action_timestamp' => 'ADD INDEX idx_action_timestamp (action, timestamp)',
                    'idx_attack_type_timestamp' => 'ADD INDEX idx_attack_type_timestamp (attack_type, timestamp)',
                    'idx_severity_timestamp' => 'ADD INDEX idx_severity_timestamp (severity, timestamp)',
                ];
                break;
                
            case 'ip_lists':
                $indexes_to_add = [
                    'idx_list_type_created' => 'ADD INDEX idx_list_type_created (list_type, created_at)',
                    'idx_list_type_expires' => 'ADD INDEX idx_list_type_expires (list_type, expires_at)',
                ];
                break;
                
            case 'login_attempts':
                $indexes_to_add = [
                    'idx_username' => 'ADD INDEX idx_username (username)',
                    'idx_ip_success_timestamp' => 'ADD INDEX idx_ip_success_timestamp (ip, success, timestamp)',
                    'idx_success_timestamp' => 'ADD INDEX idx_success_timestamp (success, timestamp)',
                ];
                break;
                
            case 'file_scan_items':
                $indexes_to_add = [
                    'idx_scan_status' => 'ADD INDEX idx_scan_status (scan_id, status)',
                ];
                break;
                
            case 'malware_scan_items':
                $indexes_to_add = [
                    'idx_scan_severity' => 'ADD INDEX idx_scan_severity (scan_id, severity)',
                    'idx_scan_quarantined' => 'ADD INDEX idx_scan_quarantined (scan_id, quarantined)',
                ];
                break;
        }
        
        // Add missing indexes
        foreach ($indexes_to_add as $index_name => $index_sql) {
            if (!in_array($index_name, $existing_indexes)) {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Schema migration
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
                $wpdb->query("ALTER TABLE `$table_name` $index_sql");
            }
        }
    }
    
    /**
     * Create database tables
     */
    private static function create_tables() {
        global $wpdb;
        
        $charset_collate = $wpdb->get_charset_collate();
        
        // Logs table
        $table_logs = $wpdb->prefix . 'vietshield_logs';
        $sql_logs = "CREATE TABLE IF NOT EXISTS $table_logs (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            ip VARCHAR(45) NOT NULL,
            country VARCHAR(2) DEFAULT '',
            country_code VARCHAR(2) DEFAULT '',
            as_number VARCHAR(20) DEFAULT '',
            as_name VARCHAR(255) DEFAULT '',
            request_uri TEXT,
            request_method VARCHAR(10) DEFAULT 'GET',
            user_agent TEXT,
            referer TEXT,
            post_data LONGTEXT,
            action ENUM('allowed', 'blocked', 'monitored', 'rate_limited') DEFAULT 'allowed',
            rule_id VARCHAR(50) DEFAULT '',
            rule_matched TEXT,
            attack_type VARCHAR(50) DEFAULT '',
            severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'low',
            response_code INT(3) DEFAULT 200,
            user_id BIGINT(20) UNSIGNED DEFAULT 0,
            is_human TINYINT(1) DEFAULT 0,
            block_id VARCHAR(12) DEFAULT '',
            PRIMARY KEY (id),
            KEY idx_ip (ip),
            KEY idx_timestamp (timestamp),
            KEY idx_action (action),
            KEY idx_attack_type (attack_type),
            KEY idx_severity (severity),
            KEY idx_block_id (block_id),
            KEY idx_user_id (user_id),
            KEY idx_country (country),
            KEY idx_country_code (country_code),
            KEY idx_as_number (as_number),
            KEY idx_ip_timestamp (ip, timestamp),
            KEY idx_action_timestamp (action, timestamp),
            KEY idx_attack_type_timestamp (attack_type, timestamp),
            KEY idx_severity_timestamp (severity, timestamp)
        ) $charset_collate;";
        
        // IP lists table
        $table_ip_lists = $wpdb->prefix . 'vietshield_ip_lists';
        $sql_ip_lists = "CREATE TABLE IF NOT EXISTS $table_ip_lists (
            id INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
            ip_address VARCHAR(45) DEFAULT '',
            ip_range VARCHAR(50) DEFAULT '',
            list_type ENUM('whitelist', 'blacklist', 'temporary') DEFAULT 'blacklist',
            reason TEXT,
            hit_count INT(11) DEFAULT 0,
            expires_at DATETIME DEFAULT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            created_by BIGINT(20) UNSIGNED DEFAULT 0,
            PRIMARY KEY (id),
            KEY idx_ip_address (ip_address),
            KEY idx_list_type (list_type),
            KEY idx_expires (expires_at),
            KEY idx_list_type_created (list_type, created_at),
            KEY idx_list_type_expires (list_type, expires_at)
        ) $charset_collate;";
        
        // Rate limits table
        $table_rate_limits = $wpdb->prefix . 'vietshield_rate_limits';
        $sql_rate_limits = "CREATE TABLE IF NOT EXISTS $table_rate_limits (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            ip VARCHAR(45) NOT NULL,
            endpoint VARCHAR(100) DEFAULT 'global',
            request_count INT(11) DEFAULT 1,
            window_start INT(11) NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY idx_ip_endpoint (ip, endpoint),
            KEY idx_window (window_start)
        ) $charset_collate;";
        
        // Blocked requests summary table (for stats)
        $table_stats = $wpdb->prefix . 'vietshield_stats';
        $sql_stats = "CREATE TABLE IF NOT EXISTS $table_stats (
            id INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
            date DATE NOT NULL,
            hour TINYINT(2) DEFAULT 0,
            total_requests BIGINT(20) DEFAULT 0,
            blocked BIGINT(20) DEFAULT 0,
            rate_limited BIGINT(20) DEFAULT 0,
            threat_intel BIGINT(20) DEFAULT 0,
            sqli INT(11) DEFAULT 0,
            xss INT(11) DEFAULT 0,
            rce INT(11) DEFAULT 0,
            lfi INT(11) DEFAULT 0,
            bad_bot INT(11) DEFAULT 0,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY idx_date_hour (date, hour),
            KEY idx_date (date)
        ) $charset_collate;";
        
        // Login attempts table
        $table_login_attempts = $wpdb->prefix . 'vietshield_login_attempts';
        $sql_login_attempts = "CREATE TABLE IF NOT EXISTS $table_login_attempts (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            ip VARCHAR(45) NOT NULL,
            username VARCHAR(255) DEFAULT '',
            success TINYINT(1) DEFAULT 0,
            user_agent TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_ip (ip),
            KEY idx_timestamp (timestamp),
            KEY idx_success (success),
            KEY idx_username (username),
            KEY idx_ip_timestamp (ip, timestamp),
            KEY idx_ip_success_timestamp (ip, success, timestamp),
            KEY idx_success_timestamp (success, timestamp)
        ) $charset_collate;";

        // File scanner tables
        $table_file_scans = $wpdb->prefix . 'vietshield_file_scans';
        $sql_file_scans = "CREATE TABLE IF NOT EXISTS $table_file_scans (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            finished_at DATETIME DEFAULT NULL,
            status ENUM('running', 'completed', 'failed') DEFAULT 'running',
            total_files INT(11) DEFAULT 0,
            ok_files INT(11) DEFAULT 0,
            modified_files INT(11) DEFAULT 0,
            missing_files INT(11) DEFAULT 0,
            unknown_files INT(11) DEFAULT 0,
            core_version VARCHAR(20) DEFAULT '',
            notes TEXT,
            PRIMARY KEY (id),
            KEY idx_status (status),
            KEY idx_started (started_at)
        ) $charset_collate;";

        $table_file_scan_items = $wpdb->prefix . 'vietshield_file_scan_items';
        $sql_file_scan_items = "CREATE TABLE IF NOT EXISTS $table_file_scan_items (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            scan_id BIGINT(20) UNSIGNED NOT NULL,
            file_path TEXT,
            status ENUM('modified', 'missing', 'unknown') DEFAULT 'unknown',
            expected_hash VARCHAR(32) DEFAULT '',
            actual_hash VARCHAR(32) DEFAULT '',
            file_size BIGINT(20) DEFAULT 0,
            file_mtime DATETIME DEFAULT NULL,
            file_type VARCHAR(20) DEFAULT 'core',
            PRIMARY KEY (id),
            KEY idx_scan (scan_id),
            KEY idx_status (status),
            KEY idx_scan_status (scan_id, status)
        ) $charset_collate;";

        // Malware scanner tables
        $table_malware_scans = $wpdb->prefix . 'vietshield_malware_scans';
        $sql_malware_scans = "CREATE TABLE IF NOT EXISTS $table_malware_scans (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            finished_at DATETIME DEFAULT NULL,
            status ENUM('running', 'completed', 'failed') DEFAULT 'running',
            scope VARCHAR(20) DEFAULT 'all',
            total_files INT(11) DEFAULT 0,
            clean_files INT(11) DEFAULT 0,
            infected_files INT(11) DEFAULT 0,
            suspicious_files INT(11) DEFAULT 0,
            notes TEXT,
            PRIMARY KEY (id),
            KEY idx_status (status),
            KEY idx_started (started_at)
        ) $charset_collate;";

        $table_malware_scan_items = $wpdb->prefix . 'vietshield_malware_scan_items';
        $sql_malware_scan_items = "CREATE TABLE IF NOT EXISTS $table_malware_scan_items (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            scan_id BIGINT(20) UNSIGNED NOT NULL,
            file_path TEXT,
            file_type VARCHAR(20) DEFAULT 'plugin',
            severity ENUM('critical', 'high', 'medium', 'low') DEFAULT 'low',
            findings LONGTEXT,
            file_size BIGINT(20) DEFAULT 0,
            file_mtime DATETIME DEFAULT NULL,
            quarantined TINYINT(1) DEFAULT 0,
            PRIMARY KEY (id),
            KEY idx_scan (scan_id),
            KEY idx_severity (severity),
            KEY idx_quarantined (quarantined),
            KEY idx_scan_severity (scan_id, severity),
            KEY idx_scan_quarantined (scan_id, quarantined)
        ) $charset_collate;";

        // Threat Intelligence table
        $table_threat_intel = $wpdb->prefix . 'vietshield_threat_intel';
        $sql_threat_intel = "CREATE TABLE IF NOT EXISTS $table_threat_intel (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            ip_address VARCHAR(45) NOT NULL,
            country_code VARCHAR(2) DEFAULT '',
            as_number VARCHAR(20) DEFAULT '',
            organization VARCHAR(255) DEFAULT '',
            last_updated DATETIME DEFAULT NULL,
            category VARCHAR(10) DEFAULT '',
            PRIMARY KEY (id),
            UNIQUE KEY idx_ip (ip_address),
            KEY idx_category (category),
            KEY idx_country (country_code)
        ) $charset_collate;";
        
        // Threats Sharing Queue table
        $table_threats_queue = $wpdb->prefix . 'vietshield_threats_queue';
        $sql_threats_queue = "CREATE TABLE IF NOT EXISTS $table_threats_queue (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            ip VARCHAR(45) NOT NULL,
            reason TEXT,
            attack_type VARCHAR(50) DEFAULT '',
            severity VARCHAR(20) DEFAULT 'medium',
            country_code VARCHAR(2) DEFAULT '',
            as_number VARCHAR(20) DEFAULT '',
            organization VARCHAR(255) DEFAULT '',
            domain VARCHAR(255) DEFAULT '',
            submitted TINYINT(1) DEFAULT 0,
            retries INT(11) DEFAULT 0,
            submitted_at DATETIME DEFAULT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_ip (ip),
            KEY idx_submitted (submitted),
            KEY idx_retries (retries),
            KEY idx_created (created_at)
        ) $charset_collate;";
        
        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql_logs);
        dbDelta($sql_ip_lists);
        dbDelta($sql_rate_limits);
        dbDelta($sql_stats);
        dbDelta($sql_login_attempts);
        dbDelta($sql_file_scans);
        dbDelta($sql_file_scan_items);
        dbDelta($sql_malware_scans);
        dbDelta($sql_malware_scan_items);
        dbDelta($sql_threat_intel);
        dbDelta($sql_threats_queue);
        
        // Store DB version
        update_option('vietshield_db_version', VIETSHIELD_DB_VERSION);
    }
    
    /**
     * Set default options
     */
    private static function set_default_options() {
        $default_options = [
            'waf_enabled' => true,
            'firewall_mode' => 'protecting', // learning, protecting
            'log_all_traffic' => false,
            'log_blocked_only' => true,
            'block_sqli' => true,
            'block_xss' => true,
            'block_rce' => false, // Default OFF to avoid false positives with Google Ads
            'block_lfi' => true,
            'block_bad_bots' => true,
            // New Lua WAF rules - Enhanced security features
            'block_bad_useragents' => true,       // Block malicious User-Agents (scanners, bots)
            'block_empty_useragent' => true,      // Block empty/unknown User-Agent
            'advanced_injection_detection' => true, // Advanced POST/Cookie/Args injection detection
            // Auto-whitelist trusted IP ranges
            'whitelist_googlebot' => true,        // Auto-whitelist Googlebot IP ranges
            'rate_limiting_enabled' => true,
            'rate_limit_global' => 100, // requests per minute
            'rate_limit_login' => 20,   // login attempts per 5 minutes
            'rate_limit_xmlrpc' => 20,  // xmlrpc requests per minute
            'block_xmlrpc' => false,
            'block_author_scan' => true,
            'whitelist_admins' => true,
            'email_alerts' => false,
            'alert_email' => get_option('admin_email'),
            'auto_block_threshold' => 10, // auto block IP after 10 attacks
            'auto_block_duration' => 3600, // 1 hour
            'log_retention_days' => 30,
            'trusted_proxies' => [],
            'whitelisted_ips' => [],
            'blacklisted_ips' => [],
            'blocked_countries' => [],
            'country_blocking_enabled' => false,
            'block_unknown_countries' => false,
            'log_timezone' => get_option('timezone_string') ?: 'UTC', // Use WordPress timezone or UTC
            'login_security_enabled' => true,
            'login_max_attempts' => 5,
            'login_time_window' => 900, // 15 minutes
            'login_lockout_duration' => 900, // 15 minutes
            'login_notifications_enabled' => false,
            'login_notification_threshold' => 3,
            'login_honeypot_enabled' => true,
            'file_scanner_enabled' => true,
            'file_scan_schedule' => 'weekly',
            'malware_scanner_enabled' => true,
            'malware_scan_schedule' => 'weekly',
            'malware_scan_scope' => 'all',
            'threat_intel_enabled' => true, // Enable by default
            'threat_intel_category' => '1d', // Default to 1d category
            'log_retention_days' => 30, // Keep logs for 30 days
            'early_blocking_enabled' => true, // Enable early blocking for performance
            // RCE Whitelist Patterns (to avoid blocking Google Ads and legitimate traffic)
            'rce_whitelist_patterns' => [
                // Google Ads patterns
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
                // Google SafeFrame patterns
                '/safeframe\.googlesyndication\.com/i',
                '/googlesyndication\.com/i',
                '/googleadservices\.com/i',
                '/doubleclick\.net/i',
                // Google Analytics patterns
                '/google-analytics\.com/i',
                '/googletagmanager\.com/i',
                // Common Google URL parameters
                '/[?&](typ|src|mdm|cmp|cnt|trm|id|plt)=/i',
            ],
        ];
        
        // Only set if not already exists
        if (!get_option('vietshield_options')) {
            add_option('vietshield_options', $default_options);
            
            // Whitelist current admin IP immediately after activation
            self::whitelist_current_admin_ip();
            
            // Auto-sync threat intelligence on first activation (after options are saved)
            // Use wp_schedule_single_event to run after activation completes
            if (!empty($default_options['threat_intel_enabled']) && !empty($default_options['threat_intel_category'])) {
                wp_schedule_single_event(time() + 5, 'vietshield_threat_intel_initial_sync');
            }

            // Auto-whitelist Googlebot immediately
            if (!empty($default_options['whitelist_googlebot'])) {
                wp_schedule_single_event(time() + 10, 'vietshield_ip_whitelist_sync');
            }
        } else {
            // Update existing options to ensure defaults are set
            $existing_options = get_option('vietshield_options', []);
            $needs_update = false;
            
            // Ensure whitelist_admins is set to true by default
            if (!isset($existing_options['whitelist_admins'])) {
                $existing_options['whitelist_admins'] = true;
                $needs_update = true;
            }
            
            // Ensure rate limits have correct defaults (only if not set)
            if (!isset($existing_options['rate_limit_global'])) {
                $existing_options['rate_limit_global'] = 100;
                $needs_update = true;
            }
            if (!isset($existing_options['rate_limit_login'])) {
                $existing_options['rate_limit_login'] = 20;
                $needs_update = true;
            }
            if (!isset($existing_options['rate_limit_xmlrpc'])) {
                $existing_options['rate_limit_xmlrpc'] = 20;
                $needs_update = true;
            }
            
            if ($needs_update) {
                update_option('vietshield_options', $existing_options);
            }
        }
    }
    
    /**
     * Create default rules files if not exist
     */
    private static function create_rules_files() {
        $rules_dir = VIETSHIELD_PLUGIN_DIR . 'rules/';
        
        // Default files are already included with the plugin
        // This ensures they exist
        $default_files = [
            'sqli-rules.json',
            'xss-rules.json',
            'rce-rules.json',
            'lfi-rules.json',
            'bad-bots.json',
            'custom-rules.json'
        ];
        
        foreach ($default_files as $file) {
            $filepath = $rules_dir . $file;
            if (!file_exists($filepath)) {
                // Create empty rules file
                file_put_contents($filepath, json_encode(['rules' => []], JSON_PRETTY_PRINT));
            }
        }
    }
    
    /**
     * Create early blocker files if not exist
     */
    private static function create_early_blocker_files() {
        $blocker_file = WP_CONTENT_DIR . '/vietshield-blocker.php';
        $blocked_ips_file = WP_CONTENT_DIR . '/vietshield-blocked-ips.php';
        
        // Create blocker file if not exists - copy from template
        if (!file_exists($blocker_file)) {
            $template_file = VIETSHIELD_PLUGIN_DIR . 'templates/early-blocker.php.tpl';
            if (file_exists($template_file)) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
                file_put_contents($blocker_file, file_get_contents($template_file));
            }
        }
        
        // Create blocked IPs file if not exists - copy from template
        if (!file_exists($blocked_ips_file)) {
            $template_file = VIETSHIELD_PLUGIN_DIR . 'templates/blocked-ips.php.tpl';
            if (file_exists($template_file)) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
                file_put_contents($blocked_ips_file, file_get_contents($template_file));
            }
        }
    }
    
    /**
     * Schedule cron jobs
     */
    private static function schedule_cron_jobs() {
        // Clean old logs daily
        if (!wp_next_scheduled('vietshield_cleanup_logs')) {
            wp_schedule_event(time(), 'daily', 'vietshield_cleanup_logs');
        }
        
        // Update threat feed daily
        if (!wp_next_scheduled('vietshield_update_threat_feed')) {
            wp_schedule_event(time(), 'daily', 'vietshield_update_threat_feed');
        }
        
        // Aggregate stats hourly
        if (!wp_next_scheduled('vietshield_aggregate_stats')) {
            wp_schedule_event(time(), 'hourly', 'vietshield_aggregate_stats');
        }
        
        // Weekly maintenance tasks
        if (!wp_next_scheduled('vietshield_maintenance')) {
            wp_schedule_event(time(), 'weekly', 'vietshield_maintenance');
        }
        
        // Threats Sharing - Submit queue every 5 minutes (always enabled)
        if (!wp_next_scheduled('vietshield_submit_threats')) {
            wp_schedule_event(time(), 'vietshield_5minutes', 'vietshield_submit_threats');
        }
        
        // Schedule threat intelligence sync if enabled
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-threat-intelligence.php';
        \VietShield\Firewall\ThreatIntelligence::schedule_sync();

        // File scan schedule
        $options = get_option('vietshield_options', []);
        $enabled = $options['file_scanner_enabled'] ?? true;
        $schedule = $options['file_scan_schedule'] ?? 'weekly';
        if ($enabled && $schedule !== 'manual' && !wp_next_scheduled('vietshield_file_scan_event')) {
            $recurrence = $schedule === 'weekly' ? 'weekly' : 'daily';
            wp_schedule_event(time(), $recurrence, 'vietshield_file_scan_event');
        }
        
        // Malware scan schedule
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/scanner/class-malware-scanner.php';
        \VietShield\Scanner\MalwareScanner::reschedule($options);
        
        // IP Whitelist sync (Googlebot, Cloudflare) - Daily
        if (!wp_next_scheduled('vietshield_ip_whitelist_sync')) {
            wp_schedule_event(time() + 60, 'daily', 'vietshield_ip_whitelist_sync');
        }
        
        // Setup early blocker
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-early-blocker.php';
        $early_blocker = new \VietShield\Firewall\EarlyBlocker();
        
        // Ensure early blocker files exist
        self::create_early_blocker_files();
        
        // Enable early blocking based on web server detection
        // This will automatically detect Nginx/Apache and configure accordingly
        $options = get_option('vietshield_options', []);
        $early_blocking_enabled = $options['early_blocking_enabled'] ?? true;
        
        if ($early_blocking_enabled) {
            // Enable early blocking (will detect web server and configure appropriately)
            $early_blocker->enable();
        } else {
            // Disable early blocking
            $early_blocker->disable();
        }
        
        // Sync blocked IPs
        $early_blocker->sync_blocked_ips();
    }
}
