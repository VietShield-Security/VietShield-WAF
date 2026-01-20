<?php
/**
 * Early Blocker
 *
 * Manages early IP blocking using .user.ini or .htaccess
 * to block IPs before WordPress loads for maximum performance.
 *
 * @package VietShield_WAF
 */

namespace VietShield\Firewall;

if (!defined('ABSPATH')) {
    exit;
}

class EarlyBlocker {
    
    /**
     * Path to blocker file
     */
    private $blocker_file;
    
    /**
     * Path to blocked IPs file
     */
    private $blocked_ips_file;
    
    /**
     * Path to binary blocked IPs file
     */
    private $item_file_bin;
    
    /**
     * Path to .user.ini file
     */
    private $user_ini_file;
    
    /**
     * Path to .htaccess file
     */
    private $htaccess_file;
    
    /**
     * Constructor
     */
    public function __construct() {
        $this->blocker_file = WP_CONTENT_DIR . '/vietshield-blocker.php';
        $this->blocked_ips_file = WP_CONTENT_DIR . '/vietshield-blocked-ips.php';
        $this->item_file_bin = WP_CONTENT_DIR . '/vietshield-blocked-ips.bin';
        $this->user_ini_file = ABSPATH . '.user.ini';
        $this->htaccess_file = ABSPATH . '.htaccess';
    }
    
    /**
     * Check if early blocking is enabled
     */
    public static function is_enabled() {
        $options = get_option('vietshield_options', []);
        // Early blocking is enabled if:
        // 1. early_blocking_enabled is explicitly set to true, OR
        // 2. firewall_mode is set to 'protecting' (Protecting Mode - Block threats and Logging)
        $firewall_mode = $options['firewall_mode'] ?? 'protecting';
        $early_blocking_enabled = $options['early_blocking_enabled'] ?? false;
        
        return !empty($early_blocking_enabled) || $firewall_mode === 'protecting';
    }
    
    /**
     * Sync blocked IPs to file
     * 
     * @return array|false Returns array with success status and message, or false on failure
     */
    public function sync_blocked_ips() {
        global $wpdb;
        
        // Sync early_blocking_enabled with firewall_mode before checking
        $options = get_option('vietshield_options', []);
        $firewall_mode = $options['firewall_mode'] ?? 'protecting';
        $early_blocking_enabled = ($firewall_mode === 'protecting');
        
        // Update early_blocking_enabled if needed
        // Note: We don't update here to avoid triggering update_option hook
        // The main settings save will handle this
        // Just return the correct value, don't update option here
        if (($options['early_blocking_enabled'] ?? false) !== $early_blocking_enabled) {
            // Don't update option here - it will cause infinite loop
            // The value will be synced in handle_options_update hook
            // Just log for debugging if needed
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
            error_log('VietShield: early_blocking_enabled needs sync, but skipping update to avoid loop');
        }
        
        if (!self::is_enabled()) {
            $this->disable();
            return [
                'success' => false,
                'message' => 'Protecting Mode is not enabled. Please enable "Protecting Mode - Block threats and Logging" in General Settings first.'
            ];
        }
        
        // Get all blocked IPs from database
        $ip_table = $wpdb->prefix . 'vietshield_ip_lists';
        $threat_table = $wpdb->prefix . 'vietshield_threat_intel';
        
        $blocked_ips = [
            'exact' => [],
            'ranges' => [],
            'trusted_proxies' => $options['trusted_proxies'] ?? [],
            'updated' => gmdate('Y-m-d H:i:s'),
        ];
        
        // Get blacklisted IPs (permanent + temporary)
        // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name is safe, no user input
        $blacklist = $wpdb->get_results(
            "SELECT ip_address, ip_range, reason, list_type 
             FROM {$ip_table} 
             WHERE list_type IN ('blacklist', 'temporary') 
             AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP())",
            ARRAY_A
        );
        
        foreach ($blacklist as $entry) {
            if (!empty($entry['ip_address'])) {
                $blocked_ips['exact'][$entry['ip_address']] = $entry['reason'] ?? 'Blacklisted';
            }
            if (!empty($entry['ip_range'])) {
                $blocked_ips['ranges'][$entry['ip_range']] = $entry['reason'] ?? 'Blacklisted';
            }
        }
        
        // Get threat intelligence IPs (if enabled)
        $options = get_option('vietshield_options', []);
        if (!empty($options['threat_intel_enabled'])) {
            // Fetch ALL threat IPs (no limit) - we use binary file now so size is fine
            $threat_ips = $wpdb->get_results(
                "SELECT DISTINCT ip_address FROM {$threat_table}",
                ARRAY_A
            );
            
            foreach ($threat_ips as $entry) {
                if (!empty($entry['ip_address'])) {
                    $blocked_ips['exact'][$entry['ip_address']] = 'Threat Intelligence';
                }
            }
        }
        
        // Get Cloudflare IPs if enabled
        if (!empty($options['cloudflare_enabled'])) {
            if (!class_exists('\\VietShield\\Integrations\\Cloudflare')) {
                require_once VIETSHIELD_PLUGIN_DIR . 'includes/integrations/class-cloudflare.php';
            }
            $cloudflare = new \VietShield\Integrations\Cloudflare();
            $cf_ranges = $cloudflare->get_ip_ranges();
            if (!empty($cf_ranges)) {
                // Merge with existing trusted proxies
                $blocked_ips['trusted_proxies'] = array_merge(
                    $blocked_ips['trusted_proxies'], 
                    $cf_ranges
                );
                // Deduplicate
                $blocked_ips['trusted_proxies'] = array_unique($blocked_ips['trusted_proxies']);
                
                // IMPORTANT: Save back to options so they appear in UI
                $current_trusted = $options['trusted_proxies'] ?? [];
                $new_trusted = array_unique(array_merge($current_trusted, $cf_ranges));
                
                // Only update if changed prevents infinite loop or unnecessary writes
                // However, array comparison can be tricky.
                // Let's just check count difference or simple array_diff
                if (count($new_trusted) !== count($current_trusted)) {
                    $options['trusted_proxies'] = $new_trusted;
                    // We must use update_option but skip sanitization loop potential
                    // Actually, we are safe here because we are in sync_blocked_ips, unrelated to options save hook if triggered manually
                    // But if triggered via options save hook, we might loop.
                    // But this is usually triggered via AJAX or Wizard.
                    // Let's protect against loop by checking backtrace? No, too complex.
                    // Just update if different.
                    update_option('vietshield_options', $options);
                }
            }
        }
        
        // Get static blacklist from options
        $static_blacklist = $options['blacklisted_ips'] ?? [];
        foreach ($static_blacklist as $ip) {
            $ip = trim($ip);
            if (!empty($ip)) {
                if (strpos($ip, '/') !== false) {
                    $blocked_ips['ranges'][$ip] = 'Blacklisted';
                } else {
                    $blocked_ips['exact'][$ip] = 'Blacklisted';
                }
            }
        }
        
        // Ensure directory is writable
        $blocked_ips_dir = dirname($this->blocked_ips_file);
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Performance critical early blocker code
        if (!is_writable($blocked_ips_dir)) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
            error_log('VietShield: Blocked IPs directory is not writable: ' . $blocked_ips_dir);
            return [
                'success' => false,
                'message' => 'Cannot write to blocked IPs file. Directory is not writable: ' . $blocked_ips_dir
            ];
        }
        
        // Check if file exists and is writable
        if (file_exists($this->blocked_ips_file)) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Performance critical
            if (!is_writable($this->blocked_ips_file)) {
                // Try to make file writable
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Performance critical
                @chmod($this->blocked_ips_file, 0644);
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Performance critical
                if (!is_writable($this->blocked_ips_file)) {
                    // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
                    error_log('VietShield: Blocked IPs file exists but is not writable: ' . $this->blocked_ips_file);
                    return [
                        'success' => false,
                        'message' => 'Blocked IPs file exists but is not writable. Please change file permissions or owner. File: ' . $this->blocked_ips_file
                    ];
                }
            }
        }
        
        // Collect all exact IPs for binary storage (IPv4 only)
        $binary_ips = [];
        $ipv6_ips = [];
        
        foreach ($blocked_ips['exact'] as $ip => $reason) {
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $binary_ips[] = ip2long($ip);
            } else {
                // Keep IPv6 in the PHP array
                $ipv6_ips[$ip] = $reason;
            }
        }
        
        // Remove exact IPs from PHP array to save memory/size in the config file
        // BUT keep IPv6 IPs as they are not supported in binary file yet
        $blocked_ips['exact'] = $ipv6_ips; 

        // Sort IPs for binary search
        sort($binary_ips, SORT_NUMERIC);
        $binary_ips = array_unique($binary_ips);
        
        // Pack into binary format: [count: 4 bytes] [ip: 4 bytes]...
        $packed_data = pack('N', count($binary_ips));
        foreach ($binary_ips as $ip_long) {
            if ($ip_long !== false) {
                $packed_data .= pack('N', $ip_long);
            }
        }
        
        // Write binary file
        $bin_result = @file_put_contents($this->item_file_bin, $packed_data, LOCK_EX);
        if ($bin_result === false) {
             error_log('VietShield: Failed to write binary IPs file');
        } else {
            @chmod($this->item_file_bin, 0644);
        }

        // Write PHP config file (without giant IP list)
        $content = "<?php\n";
        $content .= "/**\n";
        $content .= " * VietShield Blocked IPs Configuration\n";
        $content .= " * Auto-generated - DO NOT EDIT MANUALLY\n";
        $content .= " * This file contains configuration. Actual IPs are in vietshield-blocked-ips.bin\n";
        $content .= " * Last updated: {$blocked_ips['updated']}\n";
        $content .= " */\n\n";
        $content .= "return " . var_export($blocked_ips, true) . ";\n";
        
        $result = @file_put_contents($this->blocked_ips_file, $content, LOCK_EX);
        
        if ($result === false) {
            $error = error_get_last();
            $error_msg = $error['message'] ?? 'Unknown error';
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
            error_log('VietShield: Failed to write blocked IPs file: ' . $error_msg);
            
            // Try to get more info about the file
            $file_info = '';
            if (file_exists($this->blocked_ips_file)) {
                $perms = substr(sprintf('%o', fileperms($this->blocked_ips_file)), -4);
                $owner = posix_getpwuid(fileowner($this->blocked_ips_file));
                $file_info = sprintf(' (perms: %s, owner: %s)', $perms, $owner['name'] ?? 'unknown');
            }
            
            return [
                'success' => false,
                'message' => 'Failed to write blocked IPs file. Please check file permissions.' . $file_info . ' Error: ' . $error_msg
            ];
        }
        
        // Ensure file has correct permissions after writing
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Performance critical
        @chmod($this->blocked_ips_file, 0644);
        
        // Ensure blocker file exists and is up to date
        $this->ensure_blocker_file();
        
        if (!file_exists($this->blocker_file)) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
            error_log('VietShield: Blocker file not found at ' . $this->blocker_file);
            return [
                'success' => false,
                'message' => 'Blocker file not found. Please deactivate and reactivate the plugin.'
            ];
        }
        
        // Enable in .user.ini or .htaccess
        $enable_result = $this->enable();
        if (!$enable_result) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
            error_log('VietShield: Failed to enable early blocking in .user.ini/.htaccess');
            // Don't fail completely - file sync was successful
        }
        
        $total_ips = count($blocked_ips['exact']) + count($blocked_ips['ranges']);
        
        return [
            'success' => true,
            'message' => sprintf('Successfully synced %d blocked IPs', $total_ips),
            'total_ips' => $total_ips
        ];
        
        // Final step: Ensure the blocker mechanism file itself is up to date
        // This ensures template changes (like logging fixes) are propagated
        $this->ensure_blocker_file();
        
        return $result;
    }
    
    /**
     * Ensure blocker file exists and is up to date from template
     */
    private function ensure_blocker_file() {
        $template_file = VIETSHIELD_PLUGIN_DIR . 'templates/early-blocker.php.tpl';
        
        if (!file_exists($template_file)) {
            return false;
        }
        
        // Check if blocker file needs update (compare with template)
        $needs_update = false;
        
        if (!file_exists($this->blocker_file)) {
            $needs_update = true;
        } else {
            // Check if template is newer or different
            $template_content = file_get_contents($template_file);
            $blocker_content = file_get_contents($this->blocker_file);
            
            // Compare content hashes ignoring whitespace/comments if possible, but exact match is fine
            // Since we copy relevant parts, exact match of full content might be tricky if we processed it.
            // But usually we just copy the template.
            if (md5($template_content) !== md5($blocker_content)) {
                $needs_update = true;
            }
        }
        
        if ($needs_update) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Performance critical
            $result = file_put_contents($this->blocker_file, file_get_contents($template_file), LOCK_EX);
            
            if ($result !== false) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Performance critical
                @chmod($this->blocker_file, 0644);
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
                error_log('VietShield: Regenerated blocker file from template');
                return true;
            }
        }
        
        return true;
    }
    
    /**
     * Detect web server type
     */
    private function detect_web_server() {
        // Priority 1: Check SERVER_SOFTWARE (most reliable)
        $server_software = $_SERVER['SERVER_SOFTWARE'] ?? '';
        
        if (!empty($server_software)) {
            if (stripos($server_software, 'nginx') !== false) {
                return 'nginx';
            }
            
            if (stripos($server_software, 'apache') !== false) {
                return 'apache';
            }
        }
        
        // Priority 2: Check HTTP headers (for Nginx behind proxy)
        $server_name = $_SERVER['SERVER_NAME'] ?? '';
        $http_host = $_SERVER['HTTP_HOST'] ?? '';
        
        // Check if running behind Nginx (common setup)
        if (!empty($_SERVER['HTTP_X_REAL_IP']) || !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            // Could be behind Nginx proxy, but we can't be 100% sure
            // So we'll check other indicators
        }
        
        // Priority 3: Check Apache-specific functions
        if (function_exists('apache_get_modules')) {
            $modules = apache_get_modules();
            if (in_array('mod_rewrite', $modules) || in_array('mod_php', $modules)) {
                return 'apache';
            }
        }
        
        // Priority 4: Check .htaccess (but this is unreliable - WordPress always has .htaccess)
        // We'll skip this check because WordPress always creates .htaccess even on Nginx
        
        // Priority 5: Check if .user.ini exists and is being used (PHP-FPM indicator)
        if (file_exists($this->user_ini_file)) {
            $user_ini_content = file_get_contents($this->user_ini_file);
            // If .user.ini has auto_prepend_file, it's likely PHP-FPM
            if (strpos($user_ini_content, 'auto_prepend_file') !== false) {
                // Could be either Apache or Nginx with PHP-FPM
                // Default to php-fpm which works with both
                return 'php-fpm';
            }
        }
        
        // Default: assume PHP-FPM (works with both Apache and Nginx)
        // This is the safest assumption for modern setups
        return 'php-fpm';
    }
    
    /**
     * Enable early blocking
     */
    public function enable() {
        $server = $this->detect_web_server();
        
        // ALWAYS enable .user.ini first (works with PHP-FPM on both Apache and Nginx)
        // This is the primary method for modern PHP setups
        // .user.ini works with:
        // - Apache + PHP-FPM
        // - Nginx + PHP-FPM
        // - Any setup using PHP-FPM
        // Check if file exists and is writable, or if we can create it
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Performance critical
        if (file_exists($this->user_ini_file) && is_writable($this->user_ini_file)) {
            $this->enable_user_ini();
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Performance critical
        } elseif (is_writable(ABSPATH)) {
            $this->enable_user_ini();
        } else {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
            error_log('VietShield: Cannot enable .user.ini - neither file nor ABSPATH is writable');
        }
        
        // Only enable .htaccess for CONFIRMED Apache (not php-fpm or nginx)
        // .htaccess only works with Apache + mod_php (not PHP-FPM)
        if ($server === 'apache') {
            // Double-check: only enable if we're really sure it's Apache
            $server_software = $_SERVER['SERVER_SOFTWARE'] ?? '';
            if (stripos($server_software, 'apache') !== false || function_exists('apache_get_modules')) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Performance critical
                if (file_exists($this->htaccess_file) || is_writable(ABSPATH)) {
                    $this->enable_htaccess();
                }
            }
        } else {
            // Remove .htaccess markers if not Apache (cleanup for Nginx/php-fpm)
            // Nginx doesn't read .htaccess, so we should clean it up
            $this->remove_markers($this->htaccess_file, '# BEGIN VietShield Early Blocker', '# END VietShield Early Blocker');
        }
    }
    
    /**
     * Enable in .user.ini
     */
    private function enable_user_ini() {
        // Check if .user.ini file is writable or if we can create it
        if (file_exists($this->user_ini_file)) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Performance critical
            if (!is_writable($this->user_ini_file)) {
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
                error_log('VietShield: .user.ini exists but is not writable');
                return false;
            }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Performance critical
        } elseif (!is_writable(ABSPATH)) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
            error_log('VietShield: Cannot create .user.ini - ABSPATH is not writable');
            return false;
        }
        
        // .user.ini requires relative path from the directory where .user.ini is located (ABSPATH)
        // OR absolute path
        // Use absolute path for reliability
        $blocker_path = $this->blocker_file;
        
        // Ensure path uses forward slashes (Windows compatibility)
        $blocker_path = str_replace('\\', '/', $blocker_path);
        
        $marker_start = '; BEGIN VietShield Early Blocker';
        $marker_end = '; END VietShield Early Blocker';
        
        $rules = "\n{$marker_start}\n";
        $rules .= "auto_prepend_file = \"{$blocker_path}\"\n";
        $rules .= "{$marker_end}\n";
        
        $result = $this->insert_with_markers($this->user_ini_file, $marker_start, $marker_end, $rules);
        
        if ($result) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
            error_log('VietShield: Successfully configured .user.ini for early blocking');
        } else {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
            error_log('VietShield: Failed to configure .user.ini for early blocking');
        }
        
        return $result;
    }
    
    /**
     * Enable in .htaccess
     */
    private function enable_htaccess() {
        // .htaccess requires relative path from document root OR absolute path
        // Use absolute path for reliability
        $blocker_path = $this->blocker_file;
        
        // Ensure path uses forward slashes (Windows compatibility)
        $blocker_path = str_replace('\\', '/', $blocker_path);
        
        $marker_start = '# BEGIN VietShield Early Blocker';
        $marker_end = '# END VietShield Early Blocker';
        
        $rules = "\n{$marker_start}\n";
        $rules .= "<IfModule mod_php7.c>\n";
        $rules .= "  php_value auto_prepend_file \"{$blocker_path}\"\n";
        $rules .= "</IfModule>\n";
        $rules .= "<IfModule mod_php8.c>\n";
        $rules .= "  php_value auto_prepend_file \"{$blocker_path}\"\n";
        $rules .= "</IfModule>\n";
        $rules .= "{$marker_end}\n";
        
        return $this->insert_with_markers($this->htaccess_file, $marker_start, $marker_end, $rules);
    }
    
    /**
     * Disable early blocking
     */
    public function disable() {
        $this->remove_markers($this->user_ini_file, '; BEGIN VietShield Early Blocker', '; END VietShield Early Blocker');
        $this->remove_markers($this->htaccess_file, '# BEGIN VietShield Early Blocker', '# END VietShield Early Blocker');
    }
    
    /**
     * Insert content with markers (similar to WordPress insert_with_markers)
     */
    private function insert_with_markers($filename, $marker_start, $marker_end, $content) {
        if (!file_exists($filename)) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Performance critical
            if (!is_writable(dirname($filename))) {
                return false;
            }
            file_put_contents($filename, '');
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Performance critical
        } elseif (!is_writable($filename)) {
            return false;
        }
        
        $file_content = file_get_contents($filename);
        
        // Remove existing markers
        $pattern = '/\s*' . preg_quote($marker_start, '/') . '.*?' . preg_quote($marker_end, '/') . '\s*/s';
        $file_content = preg_replace($pattern, '', $file_content);
        
        // Insert new content
        if (strpos($file_content, $marker_start) === false) {
            $file_content .= $content;
        }
        
        return file_put_contents($filename, $file_content, LOCK_EX) !== false;
    }
    
    /**
     * Remove markers from file
     */
    private function remove_markers($filename, $marker_start, $marker_end) {
        if (!file_exists($filename)) {
            return true;
        }
        
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Performance critical
        if (!is_writable($filename)) {
            return false;
        }
        
        $file_content = file_get_contents($filename);
        $pattern = '/\s*' . preg_quote($marker_start, '/') . '.*?' . preg_quote($marker_end, '/') . '\s*/s';
        $file_content = preg_replace($pattern, '', $file_content);
        
        return file_put_contents($filename, $file_content, LOCK_EX) !== false;
    }
    
    /**
     * Get stats
     */
    public function get_stats() {
        $blocked_ips = [];
        
        if (file_exists($this->blocked_ips_file)) {
            $blocked_ips = include $this->blocked_ips_file;
        }
        
        $server = $this->detect_web_server();
        
        // Check if .user.ini is configured
        $user_ini_configured = false;
        if (file_exists($this->user_ini_file)) {
            $user_ini_content = file_get_contents($this->user_ini_file);
            // Check for both the marker and the blocker file path
            $user_ini_configured = (
                strpos($user_ini_content, 'vietshield-blocker.php') !== false ||
                strpos($user_ini_content, 'BEGIN VietShield Early Blocker') !== false
            );
        }
        
        // Check if .htaccess is configured (only for Apache)
        $htaccess_configured = false;
        if ($server === 'apache' && file_exists($this->htaccess_file)) {
            $htaccess_content = file_get_contents($this->htaccess_file);
            $htaccess_configured = strpos($htaccess_content, 'vietshield-blocker.php') !== false;
        }
        
        // Auto-enable if Early Blocking is enabled but not configured
        if (self::is_enabled() && !$user_ini_configured && ($server === 'nginx' || $server === 'php-fpm')) {
            // Try to enable .user.ini automatically
            $this->enable();
            // Re-check after enabling
            if (file_exists($this->user_ini_file)) {
                $user_ini_content = file_get_contents($this->user_ini_file);
                $user_ini_configured = (
                    strpos($user_ini_content, 'vietshield-blocker.php') !== false ||
                    strpos($user_ini_content, 'BEGIN VietShield Early Blocker') !== false
                );
            }
        }
        
        return [
            'enabled' => self::is_enabled(),
            'web_server' => $server,
            'exact_ips' => isset($blocked_ips['exact']) ? count($blocked_ips['exact']) : 0,
            'ranges' => isset($blocked_ips['ranges']) ? count($blocked_ips['ranges']) : 0,
            'last_updated' => isset($blocked_ips['updated']) ? $blocked_ips['updated'] : '',
            'blocker_file_exists' => file_exists($this->blocker_file),
            'blocked_ips_file_exists' => file_exists($this->blocked_ips_file),
            'user_ini_configured' => $user_ini_configured,
            'htaccess_configured' => $htaccess_configured,
        ];
    }
}
