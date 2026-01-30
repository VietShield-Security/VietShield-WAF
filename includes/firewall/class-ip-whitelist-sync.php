<?php
/**
 * IP Whitelist Sync - Auto-sync Googlebot and Cloudflare IP ranges
 * 
 * @package VietShield_WAF
 */

namespace VietShield\Firewall;

if (!defined('ABSPATH')) {
    exit;
}

class IPWhitelistSync {
    
    /**
     * Googlebot JSON endpoints
     */
    private static $googlebot_urls = [
        'googlebot' => 'https://developers.google.com/search/apis/ipranges/googlebot.json',
        'special-crawlers' => 'https://developers.google.com/search/apis/ipranges/special-crawlers.json',
        'user-triggered-fetchers' => 'https://developers.google.com/search/apis/ipranges/user-triggered-fetchers.json',
        'user-triggered-fetchers-google' => 'https://developers.google.com/search/apis/ipranges/user-triggered-fetchers-google.json',
    ];
    
    
    /**
     * Sync all enabled IP whitelists
     */
    public static function sync_all() {
        $options = get_option('vietshield_options', []);
        $results = [];
        
        // Sync Googlebot IPs (whitelist bypass)
        if (!empty($options['whitelist_googlebot'])) {
            $results['googlebot'] = self::sync_googlebot();
        }
        
        // Sync Early Blocker / Cloudflare
        // This handles fetching Cloudflare IPs if enabled and regenerating the blocklist
        if (!class_exists('\\VietShield\\Firewall\\EarlyBlocker')) {
            require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-early-blocker.php';
        }
        $early_blocker = new \VietShield\Firewall\EarlyBlocker();
        $results['early_blocker'] = $early_blocker->sync_blocked_ips();
        
        // Update last sync time
        update_option('vietshield_ip_whitelist_last_sync', time());
        
        return $results;
    }
    
    /**
     * Sync Googlebot IP ranges
     */
    public static function sync_googlebot() {
        global $wpdb;
        $table = $wpdb->prefix . 'vietshield_ip_lists';
        $all_prefixes = [];
        
        foreach (self::$googlebot_urls as $type => $url) {
            $response = wp_remote_get($url, [
                'timeout' => 30,
                'sslverify' => true,
            ]);
            
            if (is_wp_error($response)) {
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
                error_log("VietShield: Failed to fetch Googlebot IPs from {$url}: " . $response->get_error_message());
                continue;
            }
            
            $body = wp_remote_retrieve_body($response);
            $data = json_decode($body, true);
            
            if (empty($data['prefixes'])) {
                continue;
            }
            
            foreach ($data['prefixes'] as $prefix) {
                if (!empty($prefix['ipv4Prefix'])) {
                    $all_prefixes[] = $prefix['ipv4Prefix'];
                }
                if (!empty($prefix['ipv6Prefix'])) {
                    $all_prefixes[] = $prefix['ipv6Prefix'];
                }
            }
        }
        
        if (empty($all_prefixes)) {
            return ['success' => false, 'count' => 0, 'error' => 'No prefixes found'];
        }
        
        // Remove old Googlebot entries
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$table} WHERE list_type = 'whitelist' AND reason LIKE %s",
                '%[Googlebot]%'
            )
        );
        
        // Insert new entries
        $inserted = 0;
        $all_prefixes = array_unique($all_prefixes);
        
        foreach ($all_prefixes as $ip) {
            $result = $wpdb->insert($table, [
                'ip_address' => $ip,
                'list_type' => 'whitelist',
                'reason' => '[Googlebot] Auto-synced from Google',
                'created_at' => current_time('mysql', 1),
                'hit_count' => 0,
            ]);
            
            if ($result) {
                $inserted++;
            }
        }
        
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
        error_log("VietShield: Synced {$inserted} Googlebot IP ranges");
        
        return ['success' => true, 'count' => $inserted];
    }
    
    /**
     * Sync Cloudflare IP ranges
     */
    public static function sync_cloudflare() {
        $options = get_option('vietshield_options', []);
        
        // Only sync if cloudflare is detected/enabled
        if (empty($options['cloudflare_enabled'])) {
            return ['success' => true, 'count' => 0, 'skipped' => true];
        }
        
        // Cloudflare publishes their IP ranges
        $cloudflare_urls = [
            'https://www.cloudflare.com/ips-v4',
            'https://www.cloudflare.com/ips-v6',
        ];
        
        $all_ips = [];
        
        foreach ($cloudflare_urls as $url) {
            $response = wp_remote_get($url, [
                'timeout' => 30,
                'sslverify' => true,
            ]);
            
            if (is_wp_error($response)) {
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
                error_log("VietShield: Failed to fetch Cloudflare IPs from {$url}: " . $response->get_error_message());
                continue;
            }
            
            $body = wp_remote_retrieve_body($response);
            $lines = explode("\n", trim($body));
            
            foreach ($lines as $line) {
                $ip = trim($line);
                if (!empty($ip)) {
                    $all_ips[] = $ip;
                }
            }
        }
        
        if (empty($all_ips)) {
            return ['success' => false, 'count' => 0, 'error' => 'No Cloudflare IPs found'];
        }
        
        // Store Cloudflare IPs in trusted_proxies option
        $options['trusted_proxies'] = array_unique($all_ips);
        update_option('vietshield_options', $options);
        
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
        error_log("VietShield: Synced " . count($all_ips) . " Cloudflare IP ranges");
        
        return ['success' => true, 'count' => count($all_ips)];
    }

    /**
     * Get sync status
     */
    public static function get_sync_status() {
        global $wpdb;
        $table = $wpdb->prefix . 'vietshield_ip_lists';
        
        // Googlebot count from database whitelist
        $googlebot_count = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$table} WHERE list_type = 'whitelist' AND reason LIKE %s",
                '%[Googlebot]%'
            )
        );
        
        $last_sync = get_option('vietshield_ip_whitelist_last_sync', 0);
        
        return [
            'googlebot_count' => (int) $googlebot_count,
            'last_sync' => $last_sync ? gmdate('Y-m-d H:i:s', $last_sync) : null,
            'next_sync' => wp_next_scheduled('vietshield_ip_whitelist_sync'),
        ];
    }
    
    /**
     * Clear all auto-synced IPs
     */
    public static function clear_all() {
        global $wpdb;
        $table = $wpdb->prefix . 'vietshield_ip_lists';
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
        $wpdb->query(
            "DELETE FROM {$table} WHERE list_type = 'whitelist' AND reason LIKE '%[Googlebot]%'"
        );
        
        delete_option('vietshield_ip_whitelist_last_sync');
    }
    
    /**
     * Schedule daily sync
     */
    public static function schedule_sync() {
        if (!wp_next_scheduled('vietshield_ip_whitelist_sync')) {
            // Schedule for tomorrow midnight (00:00)
            $time = strtotime('tomorrow midnight');
            wp_schedule_event($time, 'daily', 'vietshield_ip_whitelist_sync');
        }
    }
    
    /**
     * Unschedule sync
     */
    public static function unschedule_sync() {
        $timestamp = wp_next_scheduled('vietshield_ip_whitelist_sync');
        if ($timestamp) {
            wp_unschedule_event($timestamp, 'vietshield_ip_whitelist_sync');
        }
    }
}
