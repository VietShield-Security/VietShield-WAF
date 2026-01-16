<?php
/**
 * Login Security - Protect WordPress login
 * 
 * @package VietShield_WAF
 */

namespace VietShield\Integrations;

if (!defined('ABSPATH')) {
    exit;
}

class LoginSecurity {
    
    /**
     * Plugin options
     */
    private $options;
    
    /**
     * Database table for login attempts
     */
    private $table;
    
    /**
     * Constructor
     */
    public function __construct() {
        global $wpdb;
        $this->table = $wpdb->prefix . 'vietshield_login_attempts';
        $this->options = get_option('vietshield_options', []);
        
        // Hook into WordPress login
        add_action('wp_login_failed', [$this, 'handle_failed_login'], 10, 1);
        add_action('wp_login', [$this, 'handle_successful_login'], 10, 2);
        add_filter('authenticate', [$this, 'check_login_attempts'], 30, 3);
        add_action('login_init', [$this, 'check_brute_force']);
        
        // Add login form protection
        add_action('login_form', [$this, 'add_login_protection']);
        
        // Verify protection before authentication
        add_filter('authenticate', [$this, 'verify_login_protection'], 5, 3);
    }
    
    /**
     * Handle failed login attempt
     */
    public function handle_failed_login($username) {
        $ip = $this->get_client_ip();
        
        // Log failed attempt
        $this->log_attempt($ip, $username, false);
        
        // Check if should block
        $this->check_and_block($ip, $username);
        
        // Send notification if enabled
        if ($this->get_option('login_notifications_enabled', false)) {
            $this->send_failed_login_notification($ip, $username);
        }
    }
    
    /**
     * Handle successful login
     */
    public function handle_successful_login($username, $user) {
        $ip = $this->get_client_ip();
        
        // Log successful attempt
        $this->log_attempt($ip, $username, true);
        
        // Clear failed attempts for this IP
        $this->clear_failed_attempts($ip);
        
        // Auto-whitelist admin IP
        if (is_a($user, 'WP_User') && $user->has_cap('manage_options')) {
            $this->auto_whitelist_admin_ip($ip, $username);
        }
    }
    
    /**
     * Automatically add admin IP to whitelist
     */
    private function auto_whitelist_admin_ip($ip, $username) {
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-ip-manager.php';
        $ip_manager = new \VietShield\Firewall\IPManager();
        
        // Check if IP is already whitelisted
        if ($ip_manager->is_whitelisted($ip)) {
            return; // Already whitelisted, skip
        }
        
        // Add to whitelist with note
        $note = sprintf(
            __('Auto-whitelisted: Admin login by %s on %s', 'vietshield-waf'),
            $username,
            current_time('Y-m-d H:i:s')
        );
        
        $ip_manager->add_to_whitelist($ip, $note);
    }
    
    /**
     * Check login attempts before authentication
     */
    public function check_login_attempts($user, $username, $password) {
        // Skip if already authenticated
        if (is_a($user, 'WP_User')) {
            return $user;
        }
        
        $ip = $this->get_client_ip();
        
        // Check if IP is blocked
        if ($this->is_ip_blocked($ip)) {
            return new \WP_Error(
                'vietshield_blocked',
                __('<strong>Error:</strong> Your IP address has been temporarily blocked due to too many failed login attempts. Please try again later.', 'vietshield-waf')
            );
        }
        
        // Check brute force protection
        if ($this->is_brute_force_attempt($ip)) {
            return new \WP_Error(
                'vietshield_brute_force',
                __('<strong>Error:</strong> Too many login attempts. Please wait before trying again.', 'vietshield-waf')
            );
        }
        
        return $user;
    }
    
    /**
     * Check brute force on login page load
     */
    public function check_brute_force() {
        $ip = $this->get_client_ip();
        
        if ($this->is_ip_blocked($ip)) {
            wp_die(
                __('Your IP address has been temporarily blocked due to too many failed login attempts.', 'vietshield-waf'),
                __('Login Blocked', 'vietshield-waf'),
                ['response' => 403]
            );
        }
    }
    
    /**
     * Log login attempt
     */
    private function log_attempt($ip, $username, $success) {
        global $wpdb;
        
        $wpdb->insert($this->table, [
            'ip' => $ip,
            'username' => $username,
            'success' => $success ? 1 : 0,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'timestamp' => current_time('mysql'),
        ], [
            '%s', '%s', '%d', '%s', '%s'
        ]);
    }
    
    /**
     * Check and block IP if threshold reached
     */
    private function check_and_block($ip, $username) {
        $max_attempts = $this->get_option('login_max_attempts', 5);
        $lockout_duration = $this->get_option('login_lockout_duration', 900); // 15 minutes
        
        // Count recent failed attempts
        $failed_count = $this->get_failed_attempts_count($ip, $max_attempts * 2);
        
        if ($failed_count >= $max_attempts) {
            // Block IP temporarily
            require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-ip-manager.php';
            $ip_manager = new \VietShield\Firewall\IPManager();
            
            $ip_manager->add_to_blacklist(
                $ip,
                'temporary',
                sprintf('Auto-blocked after %d failed login attempts', $failed_count),
                $lockout_duration
            );
            
            // Log to WAF logs
            require_once VIETSHIELD_PLUGIN_DIR . 'includes/logging/class-traffic-logger.php';
            $logger = new \VietShield\Logging\TrafficLogger();
            $logger->log([
                'ip' => $ip,
                'request_uri' => '/wp-login.php',
                'request_method' => 'POST',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                'action' => 'blocked',
                'rule_id' => 'login_brute_force',
                'attack_type' => 'brute_force',
                'severity' => 'high',
            ]);
        }
    }
    
    /**
     * Check if IP is blocked
     */
    private function is_ip_blocked($ip) {
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-ip-manager.php';
        $ip_manager = new \VietShield\Firewall\IPManager();
        
        return $ip_manager->is_blacklisted($ip);
    }
    
    /**
     * Check if brute force attempt
     */
    private function is_brute_force_attempt($ip) {
        $max_attempts = $this->get_option('login_max_attempts', 5);
        $time_window = $this->get_option('login_time_window', 900); // 15 minutes
        
        $failed_count = $this->get_failed_attempts_count($ip, $time_window);
        
        return $failed_count >= $max_attempts;
    }
    
    /**
     * Get failed attempts count
     */
    private function get_failed_attempts_count($ip, $time_window = 900) {
        global $wpdb;
        
        return (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$this->table}
             WHERE ip = %s
             AND success = 0
             AND timestamp > DATE_SUB(NOW(), INTERVAL %d SECOND)",
            $ip,
            $time_window
        ));
    }
    
    /**
     * Clear failed attempts for IP
     */
    private function clear_failed_attempts($ip) {
        global $wpdb;
        
        // Only clear if there are recent failed attempts
        $wpdb->query($wpdb->prepare(
            "DELETE FROM {$this->table}
             WHERE ip = %s AND success = 0",
            $ip
        ));
    }
    
    /**
     * Add login form protection (honeypot, nonce, etc.)
     */
    public function add_login_protection() {
        // Add honeypot field
        echo '<input type="text" name="vietshield_hp" value="" style="display:none !important; visibility:hidden !important;" tabindex="-1" autocomplete="off">';
        
        // Add nonce
        wp_nonce_field('vietshield_login', 'vietshield_login_nonce');
    }
    
    /**
     * Verify login protection
     */
    public function verify_login_protection($user, $username, $password) {
        // Only check on login form submission
        if (!isset($_POST['wp-submit']) && !isset($_POST['log'])) {
            return $user;
        }
        
        // Check honeypot
        if ($this->get_option('login_honeypot_enabled', true) && !empty($_POST['vietshield_hp'])) {
            // Bot detected
            $ip = $this->get_client_ip();
            $this->log_attempt($ip, $username ?: 'bot', false);
            
            return new \WP_Error(
                'vietshield_bot',
                __('<strong>Error:</strong> Invalid login attempt detected.', 'vietshield-waf')
            );
        }
        
        // Verify nonce (optional, WordPress already has CSRF protection)
        if (isset($_POST['vietshield_login_nonce']) && 
            !wp_verify_nonce($_POST['vietshield_login_nonce'], 'vietshield_login')) {
            // Invalid nonce - might be CSRF
            $ip = $this->get_client_ip();
            $this->log_attempt($ip, $username ?: 'unknown', false);
        }
        
        return $user;
    }
    
    /**
     * Send failed login notification
     */
    private function send_failed_login_notification($ip, $username) {
        $email = $this->get_option('alert_email', get_option('admin_email'));
        $threshold = $this->get_option('login_notification_threshold', 3);
        
        $failed_count = $this->get_failed_attempts_count($ip);
        
        // Only send if threshold reached
        if ($failed_count >= $threshold) {
            $subject = sprintf(
                __('[%s] Failed Login Attempts Detected', 'vietshield-waf'),
                get_bloginfo('name')
            );
            
            $message = sprintf(
                __("Multiple failed login attempts detected:\n\nIP Address: %s\nUsername: %s\nFailed Attempts: %d\nTime: %s\n\n", 'vietshield-waf'),
                $ip,
                $username,
                $failed_count,
                current_time('mysql')
            );
            
            $message .= __('If this was not you, please secure your account immediately.', 'vietshield-waf');
            
            wp_mail($email, $subject, $message);
        }
    }
    
    /**
     * Get client IP
     */
    private function get_client_ip() {
        $headers = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_REAL_IP',
            'HTTP_X_FORWARDED_FOR',
            'REMOTE_ADDR'
        ];
        
        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = $_SERVER[$header];
                if (strpos($ip, ',') !== false) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
    
    /**
     * Get login attempts statistics
     */
    public function get_login_stats($days = 7) {
        global $wpdb;
        
        return $wpdb->get_results($wpdb->prepare(
            "SELECT DATE(timestamp) as date,
                    COUNT(*) as total_attempts,
                    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
                    SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed,
                    COUNT(DISTINCT ip) as unique_ips
             FROM {$this->table}
             WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %d DAY)
             GROUP BY DATE(timestamp)
             ORDER BY date DESC",
            $days
        ), ARRAY_A);
    }
    
    /**
     * Get recent failed login attempts
     */
    public function get_recent_failed_attempts($limit = 20) {
        global $wpdb;
        
        return $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$this->table}
             WHERE success = 0
             ORDER BY timestamp DESC
             LIMIT %d",
            $limit
        ), ARRAY_A);
    }
    
    /**
     * Get top attacking IPs
     */
    public function get_top_attacking_ips($limit = 10, $days = 7) {
        global $wpdb;
        
        return $wpdb->get_results($wpdb->prepare(
            "SELECT ip, 
                    COUNT(*) as attempt_count,
                    MAX(timestamp) as last_attempt,
                    GROUP_CONCAT(DISTINCT username) as usernames
             FROM {$this->table}
             WHERE success = 0
             AND timestamp >= DATE_SUB(NOW(), INTERVAL %d DAY)
             GROUP BY ip
             ORDER BY attempt_count DESC
             LIMIT %d",
            $days,
            $limit
        ), ARRAY_A);
    }
    
    /**
     * Cleanup old login attempts
     */
    public function cleanup($days = 30) {
        global $wpdb;
        
        return $wpdb->query($wpdb->prepare(
            "DELETE FROM {$this->table}
             WHERE timestamp < DATE_SUB(NOW(), INTERVAL %d DAY)",
            $days
        ));
    }
    
    /**
     * Get option with default
     */
    private function get_option($key, $default = null) {
        return $this->options[$key] ?? $default;
    }
}
