<?php
/**
 * Threat Intelligence
 *
 * Fetches and manages threat intelligence feeds from VietShield Intelligence API.
 *
 * @package VietShield_WAF
 */

namespace VietShield\Firewall;

if (!defined('ABSPATH')) {
    exit;
}

class ThreatIntelligence {
    
    const API_BASE = 'https://intelligence.vietshield.org/api/blocklist.php';
    const CATEGORIES = ['1d', '3d', '7d', '14d', '30d'];
    const CACHE_GROUP = 'vietshield_threat_intel';
    const CACHE_KEY_IPS = 'threat_ips';
    const CACHE_KEY_LAST_SYNC = 'last_sync';
    const CACHE_EXPIRY = 3600; // 1 hour
    
    /**
     * Get current category from options
     */
    public static function get_current_category() {
        $options = get_option('vietshield_options', []);
        return $options['threat_intel_category'] ?? '';
    }
    
    /**
     * Check if threat intelligence is enabled
     */
    public static function is_enabled() {
        $options = get_option('vietshield_options', []);
        return !empty($options['threat_intel_enabled']) && !empty($options['threat_intel_category']);
    }
    
    /**
     * Check if an IP is in the threat intelligence feed
     */
    public function is_threat_ip($ip) {
        if (!self::is_enabled()) {
            return false;
        }
        
        // Try cache first
        $cached = wp_cache_get($ip, self::CACHE_GROUP);
        if ($cached !== false) {
            return $cached === 'blocked';
        }
        
        // Check database
        global $wpdb;
        $table = $wpdb->prefix . 'vietshield_threat_intel';
        
        $exists = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$table} WHERE ip_address = %s",
            $ip
        ));
        
        $is_blocked = $exists > 0;
        
        // Cache result (1 hour)
        wp_cache_set($ip, $is_blocked ? 'blocked' : 'allowed', self::CACHE_GROUP, self::CACHE_EXPIRY);
        
        return $is_blocked;
    }
    
    /**
     * Fetch threat intelligence feed from API
     */
    public function fetch_feed($category) {
        if (!in_array($category, self::CATEGORIES, true)) {
            return [
                'success' => false,
                'error' => 'Invalid category',
            ];
        }
        
        $url = self::API_BASE . '?category=' . urlencode($category);
        
        $response = wp_remote_get($url, [
            'timeout' => 120, // 2 minutes for large feeds
            'sslverify' => true,
            'headers' => [
                'User-Agent' => 'VietShield-WAF/' . VIETSHIELD_VERSION,
            ],
        ]);
        
        if (is_wp_error($response)) {
            return [
                'success' => false,
                'error' => $response->get_error_message(),
            ];
        }
        
        $code = wp_remote_retrieve_response_code($response);
        if ($code !== 200) {
            return [
                'success' => false,
                'error' => 'HTTP ' . $code,
            ];
        }
        
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);
        
        // Log response for debugging
        if (empty($data) || !is_array($data)) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
            error_log('VietShield Threat Intel: Invalid JSON response. Body: ' . substr($body, 0, 500));
            return [
                'success' => false,
                'error' => 'Invalid JSON response',
            ];
        }
        
        if (empty($data['success']) || !isset($data['data'])) {
            $error_msg = $data['error'] ?? 'Invalid response format';
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
            error_log('VietShield Threat Intel: API error - ' . $error_msg . ' Response: ' . json_encode($data));
            return [
                'success' => false,
                'error' => $error_msg,
            ];
        }
        
        // Log success
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
        error_log('VietShield Threat Intel: Fetched ' . count($data['data']) . ' IPs from category ' . $category);
        
        return [
            'success' => true,
            'category' => $data['category'] ?? $category,
            'total' => $data['total'] ?? 0,
            'data' => $data['data'] ?? [],
        ];
    }
    
    /**
     * Sync threat intelligence feed to database
     */
    public function sync_feed($category) {
        global $wpdb;
        $table = $wpdb->prefix . 'vietshield_threat_intel';
        
        // Fetch feed
        $feed = $this->fetch_feed($category);
        
        if (!$feed['success']) {
            return [
                'success' => false,
                'error' => $feed['error'] ?? 'Failed to fetch feed',
            ];
        }
        
        // Clear existing data for this category
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
        $wpdb->query("TRUNCATE TABLE {$table}");
        
        // Clear cache (WordPress doesn't have flush_group, so we'll clear on-demand)
        
        // Insert new data in batches
        $ips = $feed['data'] ?? [];
        if (empty($ips) || !is_array($ips)) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
            error_log('VietShield Threat Intel: No IPs in feed data. Feed keys: ' . json_encode(array_keys($feed)) . ' Total: ' . ($feed['total'] ?? 0));
            return [
                'success' => false,
                'error' => 'No IPs in feed data. Total: ' . ($feed['total'] ?? 0),
            ];
        }
        
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
        error_log('VietShield Threat Intel: Starting sync for ' . count($ips) . ' IPs from category ' . $category);
        
        $batch_size = 1000;
        $inserted = 0;
        $batch = [];
        
        foreach ($ips as $item) {
            if (empty($item['ip_address'])) {
                continue;
            }
            
            $ip = sanitize_text_field($item['ip_address']);
            $country = sanitize_text_field($item['country_code'] ?? '');
            $as_number = sanitize_text_field($item['as_number'] ?? '');
            $organization = sanitize_text_field($item['organization'] ?? '');
            $last_updated = sanitize_text_field($item['last_updated'] ?? current_time('mysql', 1));
            
            $batch[] = [
                'ip_address' => $ip,
                'country_code' => $country,
                'as_number' => $as_number,
                'organization' => $organization,
                'last_updated' => $last_updated,
                'category' => $category,
            ];
            
            // Insert in batches
            if (count($batch) >= $batch_size) {
                $result = $this->insert_batch($table, $batch);
                if ($result === false) {
                    return [
                        'success' => false,
                        'error' => 'Database error: ' . $wpdb->last_error,
                    ];
                }
                $inserted += count($batch);
                $batch = [];
            }
        }
        
        // Insert remaining
        if (!empty($batch)) {
            $result = $this->insert_batch($table, $batch);
            if ($result === false) {
                return [
                    'success' => false,
                    'error' => 'Database error: ' . $wpdb->last_error,
                ];
            }
            $inserted += count($batch);
        }
        
        // Update last sync time
        update_option('vietshield_threat_intel_last_sync', current_time('mysql', 1));
        update_option('vietshield_threat_intel_sync_count', $inserted);
        
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
        error_log('VietShield Threat Intel: Sync completed. Inserted ' . $inserted . ' IPs from ' . ($feed['total'] ?? 0) . ' total');
        
        // Sync early blocker if enabled
        if (self::is_enabled()) {
            require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-early-blocker.php';
            $early_blocker = new \VietShield\Firewall\EarlyBlocker();
            $early_blocker->sync_blocked_ips();
        }
        
        return [
            'success' => true,
            'total' => $feed['total'] ?? 0,
            'inserted' => $inserted,
            'category' => $category,
        ];
    }
    
    /**
     * Get sync status
     */
    public function get_sync_status() {
        global $wpdb;
        $table = $wpdb->prefix . 'vietshield_threat_intel';
        
        $count = $wpdb->get_var("SELECT COUNT(*) FROM {$table}");
        $last_sync = get_option('vietshield_threat_intel_last_sync', '');
        
        // Format last_sync to user timezone
        if ($last_sync) {
            require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-vietshield-helpers.php';
            $last_sync = \VietShield_Helpers::format_timestamp($last_sync, 'Y-m-d H:i:s');
        }
        $category = self::get_current_category();
        
        // Get next scheduled sync time
        $next_sync = wp_next_scheduled('vietshield_threat_intel_sync');
        $next_sync_time = $next_sync ? wp_date('Y-m-d H:i:s', $next_sync) : '';
        
        return [
            'count' => (int) $count,
            'last_sync' => $last_sync,
            'category' => $category,
            'enabled' => self::is_enabled(),
            'next_sync' => $next_sync_time,
            'next_sync_timestamp' => $next_sync,
        ];
    }
    
    /**
     * Get total number of IPs synced from threat intelligence
     * 
     * @return int
     */
    public static function get_total_synced_ips() {
        global $wpdb;
        $table = $wpdb->prefix . 'vietshield_threat_intel';
        
        $count = $wpdb->get_var("SELECT COUNT(DISTINCT ip_address) FROM {$table}");
        
        return (int) $count;
    }
    
    /**
     * Get number of IPs blocked by threat intelligence
     * 
     * @param int $days Number of days to look back
     * @return int
     */
    public static function get_blocked_count($days = 7) {
        global $wpdb;
        $logs_table = $wpdb->prefix . 'vietshield_logs';
        
        // Count distinct IPs blocked by threat intelligence
        // Threat intelligence blocks are identified by attack_type = 'threat_intel' 
        // or rule_id = 'threat_intelligence'
        $count = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(DISTINCT ip) FROM {$logs_table}
             WHERE action = 'blocked'
             AND timestamp >= DATE_SUB(NOW(), INTERVAL %d DAY)
             AND (attack_type = 'threat_intel' OR rule_id = 'threat_intelligence')",
            $days
        ));
        
        return (int) $count;
    }
    
    /**
     * Clear all threat intelligence data
     */
    public function clear_data() {
        global $wpdb;
        $table = $wpdb->prefix . 'vietshield_threat_intel';
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
        $wpdb->query("TRUNCATE TABLE {$table}");
        
        delete_option('vietshield_threat_intel_last_sync');
        delete_option('vietshield_threat_intel_sync_count');
        
        return true;
    }
    
    /**
     * Get sync interval in hours based on category
     */
    public static function get_sync_interval($category) {
        $intervals = [
            '1d' => 24,   // Daily
            '3d' => 72,   // Every 3 days
            '7d' => 168,  // Weekly
            '14d' => 336, // Every 2 weeks
            '30d' => 720, // Monthly
        ];
        
        return $intervals[$category] ?? 24;
    }
    
    /**
     * Schedule automatic sync based on category
     */
    public static function schedule_sync($category = null) {
        // Clear existing schedule
        $timestamp = wp_next_scheduled('vietshield_threat_intel_sync');
        if ($timestamp) {
            wp_unschedule_event($timestamp, 'vietshield_threat_intel_sync');
        }
        
        if (empty($category)) {
            $options = get_option('vietshield_options', []);
            $category = $options['threat_intel_category'] ?? '';
        }
        
        // Only schedule if enabled and category is set
        if (empty($category) || !self::is_enabled()) {
            return false;
        }
        
        $interval = self::get_sync_interval($category);
        $next_run = time() + ($interval * HOUR_IN_SECONDS);
        
        // Schedule single event (will reschedule itself after running)
        wp_schedule_single_event($next_run, 'vietshield_threat_intel_sync');
        
        // Store category for cron handler
        update_option('vietshield_threat_intel_sync_category', $category);
        
        return true;
    }
    
    /**
     * Handle scheduled sync
     */
    public static function cron_sync() {
        $category = get_option('vietshield_threat_intel_sync_category', '');
        
        if (empty($category) || !self::is_enabled()) {
            // Clear schedule if disabled
            $timestamp = wp_next_scheduled('vietshield_threat_intel_sync');
            if ($timestamp) {
                wp_unschedule_event($timestamp, 'vietshield_threat_intel_sync');
            }
            return;
        }
        
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-threat-intelligence.php';
        $threat_intel = new self();
        
        $result = $threat_intel->sync_feed($category);
        
        if ($result['success']) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
            error_log(sprintf('VietShield: Auto-synced threat intelligence feed (%s): %s IPs', $category, number_format($result['inserted'])));
        } else {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
            error_log('VietShield: Failed to auto-sync threat intelligence feed: ' . ($result['error'] ?? 'Unknown error'));
        }
        
        // Reschedule next sync
        self::schedule_sync($category);
    }
    
    /**
     * Insert batch of records
     */
    private function insert_batch($table, $batch) {
        global $wpdb;
        
        if (empty($batch)) {
            return true;
        }
        
        $values = [];
        $placeholders = [];
        
        foreach ($batch as $row) {
            $placeholders[] = $wpdb->prepare(
                '(%s, %s, %s, %s, %s, %s)',
                $row['ip_address'],
                $row['country_code'],
                $row['as_number'],
                $row['organization'],
                $row['last_updated'],
                $row['category']
            );
        }
        
        $sql = "INSERT INTO {$table} (ip_address, country_code, as_number, organization, last_updated, category) VALUES " . implode(', ', $placeholders);
        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name safe, each value properly prepared above
        $result = $wpdb->query($sql);
        
        if ($result === false && !empty($wpdb->last_error)) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
            error_log('VietShield Threat Intel Insert Error: ' . $wpdb->last_error);
            return false;
        }
        
        return true;
    }
}
