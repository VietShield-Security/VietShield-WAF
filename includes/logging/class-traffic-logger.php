<?php
/**
 * Traffic Logger - Log all WAF events
 * 
 * @package VietShield_WAF
 */

namespace VietShield\Logging;

if (!defined('ABSPATH')) {
    exit;
}

class TrafficLogger {
    
    /**
     * Database table name
     */
    private $table;
    
    /**
     * Stats table name
     */
    private $stats_table;
    
    /**
     * Constructor
     */
    public function __construct() {
        global $wpdb;
        $this->table = $wpdb->prefix . 'vietshield_logs';
        $this->stats_table = $wpdb->prefix . 'vietshield_stats';
    }
    
    /**
     * Log a request
     * 
     * @param array $data Log data
     * @return int|false Insert ID or false on failure
     */
    public function log($data) {
        global $wpdb;
        
        // Get timestamp in configured timezone
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-vietshield-helpers.php';
        $timestamp = \VietShield_Helpers::get_current_timestamp();
        
        $defaults = [
            'timestamp' => $timestamp,
            'ip' => '',
            'country' => '',
            'request_uri' => '',
            'request_method' => 'GET',
            'user_agent' => '',
            'referer' => '',
            'post_data' => '',
            'action' => 'allowed',
            'rule_id' => '',
            'rule_matched' => '',
            'attack_type' => '',
            'severity' => 'low',
            'response_code' => 200,
            'user_id' => get_current_user_id(),
            'is_human' => 0,
            'block_id' => '',
        ];
        
        $data = wp_parse_args($data, $defaults);
        
        // Truncate long fields
        $data['request_uri'] = substr($data['request_uri'], 0, 2000);
        $data['user_agent'] = substr($data['user_agent'], 0, 500);
        $data['referer'] = substr($data['referer'], 0, 500);
        $data['rule_matched'] = substr($data['rule_matched'], 0, 500);
        
        // Set response code based on action
        if ($data['action'] === 'blocked') {
            $data['response_code'] = 403;
        } elseif ($data['action'] === 'rate_limited') {
            $data['response_code'] = 429;
        }
        
        // Insert log
        $result = $wpdb->insert($this->table, $data, [
            '%s', // timestamp
            '%s', // ip
            '%s', // country
            '%s', // request_uri
            '%s', // request_method
            '%s', // user_agent
            '%s', // referer
            '%s', // post_data
            '%s', // action
            '%s', // rule_id
            '%s', // rule_matched
            '%s', // attack_type
            '%s', // severity
            '%d', // response_code
            '%d', // user_id
            '%d', // is_human
            '%s', // block_id
        ]);
        
        // Update daily stats
        $this->update_stats($data);
        
        return $result ? $wpdb->insert_id : false;
    }
    
    /**
     * Get recent block ID for deduplication
     * 
     * @param string $ip
     * @param string $attack_type
     * @return string|null Block ID or null
     */
    public function get_recent_block_id($ip, $attack_type) {
        global $wpdb;
        
        // Check for logs within last hour with same IP and attack type
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
        $block_id = $wpdb->get_var($wpdb->prepare(
            "SELECT block_id FROM {$this->table} 
             WHERE ip = %s 
             AND attack_type = %s 
             AND action = 'blocked'
             AND timestamp > DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 HOUR) 
             ORDER BY id DESC 
             LIMIT 1",
            $ip,
            $attack_type
        ));
        
        return $block_id;
    }
    
    /**
     * Increment total requests counter in stats table
     * This is called for every request, even if not logged
     */
    public function increment_total_requests() {
        global $wpdb;
        
        // Use WP local time to match aggregation logic
        $date = wp_date('Y-m-d');
        $hour = wp_date('H');
        $updated_at = current_time('mysql');
        
        // Increment total_requests only
        $sql = "INSERT INTO {$this->stats_table} 
                (date, hour, total_requests, updated_at)
                VALUES (%s, %s, 1, %s)
                ON DUPLICATE KEY UPDATE
                total_requests = total_requests + 1,
                updated_at = %s";
                
        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Table name is safe, query properly prepared
        $wpdb->query($wpdb->prepare($sql, 
            $date, $hour, $updated_at,
            $updated_at
        ));
    }
    
    /**
     * Update daily statistics
     * Note: This method is deprecated - stats are now aggregated hourly via scheduled tasks
     * Keeping for backward compatibility but it won't work with the new schema
     */
    private function update_stats($data) {
        global $wpdb;
        
        // Use WP local time to match aggregation logic
        $date = wp_date('Y-m-d');
        $hour = wp_date('H');
        
        $blocked = ($data['action'] === 'blocked') ? 1 : 0;
        $rate_limited = ($data['action'] === 'rate_limited') ? 1 : 0;
        $threat_intel = ($data['action'] === 'threat_intelligence') ? 1 : 0;
        
        $sqli = ($data['attack_type'] === 'sqli') ? 1 : 0;
        $xss = ($data['attack_type'] === 'xss') ? 1 : 0;
        $rce = ($data['attack_type'] === 'rce') ? 1 : 0;
        $lfi = ($data['attack_type'] === 'lfi') ? 1 : 0;
        $bad_bot = ($data['attack_type'] === 'bad_bot') ? 1 : 0;
        
        $updated_at = current_time('mysql');
        
        // Use INSERT ... ON DUPLICATE KEY UPDATE for atomic incremental updates
        // Note: total_requests is now incremented separately via increment_total_requests()
        // so we don't increment it here to avoid double counting
        $sql = "INSERT INTO {$this->stats_table} 
                (date, hour, total_requests, blocked, rate_limited, threat_intel, sqli, xss, rce, lfi, bad_bot, updated_at)
                VALUES (%s, %s, 0, %d, %d, %d, %d, %d, %d, %d, %d, %s)
                ON DUPLICATE KEY UPDATE
                blocked = blocked + %d,
                rate_limited = rate_limited + %d,
                threat_intel = threat_intel + %d,
                sqli = sqli + %d,
                xss = xss + %d,
                rce = rce + %d,
                lfi = lfi + %d,
                bad_bot = bad_bot + %d,
                updated_at = %s";
                
        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Table name is safe, query properly prepared
        $wpdb->query($wpdb->prepare($sql, 
            // VALUES params
            $date, $hour, 
            $blocked, $rate_limited, $threat_intel, 
            $sqli, $xss, $rce, $lfi, $bad_bot, 
            $updated_at,
            // UPDATE params
            $blocked, $rate_limited, $threat_intel, 
            $sqli, $xss, $rce, $lfi, $bad_bot, 
            $updated_at
        ));
    }
    
    /**
     * Get logs with pagination
     * 
     * @param array $args Query arguments
     * @return array
     */
    public function get_logs($args = []) {
        global $wpdb;
        
        $defaults = [
            'per_page' => 50,
            'page' => 1,
            'orderby' => 'timestamp',
            'order' => 'DESC',
            'action' => '',
            'attack_type' => '',
            'severity' => '',
            'ip' => '',
            'block_id' => '',
            'search' => '',
            'date_from' => '',
            'date_to' => '',
        ];
        
        $args = wp_parse_args($args, $defaults);
        
        $where = ['1=1'];
        $values = [];
        
        // Filter by action
        if (!empty($args['action'])) {
            $where[] = 'action = %s';
            $values[] = $args['action'];
        }
        
        // Filter by attack type
        if (!empty($args['attack_type'])) {
            $where[] = 'attack_type = %s';
            $values[] = $args['attack_type'];
        }
        
        // Filter by severity
        if (!empty($args['severity'])) {
            $where[] = 'severity = %s';
            $values[] = $args['severity'];
        }
        
        // Filter by IP
        if (!empty($args['ip'])) {
            $where[] = 'ip = %s';
            $values[] = $args['ip'];
        }
        
        // Filter by Block ID
        if (!empty($args['block_id'])) {
            $where[] = 'block_id = %s';
            $values[] = $args['block_id'];
        }
        
        // Search
        if (!empty($args['search'])) {
            $search = '%' . $wpdb->esc_like($args['search']) . '%';
            $where[] = '(request_uri LIKE %s OR user_agent LIKE %s OR ip LIKE %s)';
            $values[] = $search;
            $values[] = $search;
            $values[] = $search;
        }
        
        // Date range
        if (!empty($args['date_from'])) {
            $where[] = 'timestamp >= %s';
            $values[] = $args['date_from'] . ' 00:00:00';
        }
        
        if (!empty($args['date_to'])) {
            $where[] = 'timestamp <= %s';
            $values[] = $args['date_to'] . ' 23:59:59';
        }
        
        $where_sql = implode(' AND ', $where);
        
        // Sanitize orderby
        $allowed_orderby = ['id', 'timestamp', 'ip', 'action', 'attack_type', 'severity'];
        $orderby = in_array($args['orderby'], $allowed_orderby) ? $args['orderby'] : 'timestamp';
        $order = strtoupper($args['order']) === 'ASC' ? 'ASC' : 'DESC';
        
        // Get total count
        $count_sql = "SELECT COUNT(*) FROM {$this->table} WHERE {$where_sql}";
        if (!empty($values)) {
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Dynamic where clause, values properly prepared
            $count_sql = $wpdb->prepare($count_sql, $values);
        }
        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Query properly prepared above
        $total = $wpdb->get_var($count_sql);
        
        // Get results
        $offset = ($args['page'] - 1) * $args['per_page'];
        $limit_sql = $wpdb->prepare("LIMIT %d OFFSET %d", $args['per_page'], $offset);
        
        $sql = "SELECT * FROM {$this->table} WHERE {$where_sql} ORDER BY {$orderby} {$order} {$limit_sql}";
        if (!empty($values)) {
            $sql = $wpdb->prepare(
                "SELECT * FROM {$this->table} WHERE {$where_sql} ORDER BY {$orderby} {$order} {$limit_sql}",
                $values
            );
        }
        
        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Query properly prepared, columns sanitized
        $results = $wpdb->get_results($sql, ARRAY_A);
        
        // Format timestamps according to configured timezone
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/class-vietshield-helpers.php';
        foreach ($results as &$log) {
            if (!empty($log['timestamp'])) {
                // Timestamp is already in configured timezone (from log() method)
                // But we ensure it's formatted correctly
                $log['timestamp'] = \VietShield_Helpers::format_timestamp($log['timestamp'], 'Y-m-d H:i:s');
            }
            
            // Enrich with IP metadata (Country, ASN Number, ASN Name)
            if (!empty($log['ip'])) {
                // Pass false to skip remote API fetch for performance
                $metadata = $this->get_ip_metadata($log['ip'], false);
                
                // Prioritize metadata from Cache/ThreatIntel > Existing Log Data
                // Do NOT overwrite existing data with empty values if get_ip_metadata returns empty (due to no remote fetch)
                
                if (!empty($metadata['country_code'])) {
                    $log['country_code'] = $metadata['country_code'];
                } elseif (empty($log['country_code']) && !empty($log['country'])) {
                    $log['country_code'] = $log['country'];
                }

                if (!empty($metadata['as_number'])) {
                    $log['as_number'] = $metadata['as_number'];
                }
                
                if (!empty($metadata['as_name'])) {
                    $log['as_name'] = $metadata['as_name'];
                }

                // Check IP Status (Whitelist/Blacklist/Temporary)
                // We need to instantiate IPManager only once, or better yet, make static calls if possible.
                // But IPManager methods are instance methods.
                // To avoid performance hit, we should potentially cache checking or instantiate once outside the loop?
                // But this method works on pagination so loop size is small (50).
                
                if (!class_exists('\\VietShield\\Firewall\\IPManager')) {
                   require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-ip-manager.php';
                }
                
                // Use a static approach or singleton if possible, but for now new instance is okay-ish as it caches heavily.
                // However, repeatedly calling new IPManager() might reload cache if not static.
                // Let's check IPManager. Cache is static `private static $cache = null;`. Good.
                
                $ip_manager = new \VietShield\Firewall\IPManager();
                
                $log['ip_status'] = 'clean';
                $log['ip_status_label'] = '';
                
                if ($ip_manager->is_whitelisted($log['ip'])) {
                    $log['ip_status'] = 'whitelisted';
                    $log['ip_status_label'] = __('Whitelisted', 'vietshield-waf');
                } elseif ($ip_manager->is_blacklisted($log['ip'])) {
                    // is_blacklisted checks both permanent and temporary.
                    // We need to distinguish for UI.
                    
                    // Check specifically for temporary using check_list logic logic which is private.
                    // But we can check is_blacklisted returns true.
                    // Let's see if we can check temporary list specifically.
                    // The get_list method is public. But that's heavy.
                    // The method get_ip_info returns the row with list_type.
                    
                    $info = $ip_manager->get_ip_info($log['ip']);
                    if ($info) {
                        if ($info['list_type'] === 'temporary') {
                             $log['ip_status'] = 'temporary';
                             $log['ip_status_label'] = __('Temp Blocked', 'vietshield-waf');
                        } elseif ($info['list_type'] === 'blacklist') {
                             $log['ip_status'] = 'blacklisted';
                             $log['ip_status_label'] = __('Blacklisted', 'vietshield-waf');
                        }
                    } else {
                        // Fallback if is_blacklisted was true but get_ip_info returned null (maybe static blacklist from options?)
                        $log['ip_status'] = 'blacklisted';
                        $log['ip_status_label'] = __('Blacklisted', 'vietshield-waf');
                    }
                }
            }
        }
        unset($log);
        
        return [
            'logs' => $results,
            'total' => (int) $total,
            'pages' => ceil($total / $args['per_page']),
            'page' => (int) $args['page'],
        ];
    }
    
    /**
     * Get IP metadata (Country, ASN Number, ASN Name)
     * First tries threat_intel table, then falls back to external API
     * 
     * @param string $ip IP address
     * @param bool $fetch_remote Whether to fetch from remote API if missing
     * @return array
     */
    private function get_ip_metadata($ip, $fetch_remote = true) {
        global $wpdb;
        
        // Try threat intelligence table first
        $threat_table = $wpdb->prefix . 'vietshield_threat_intel';
        // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name is safe, query properly prepared
        $threat_data = $wpdb->get_row($wpdb->prepare(
            "SELECT country_code, as_number, organization 
             FROM {$threat_table} 
             WHERE ip_address = %s 
             LIMIT 1",
            $ip
        ), ARRAY_A);
        
        if ($threat_data) {
            // Parse AS number and name
            $as_number_raw = $threat_data['as_number'] ?? '';
            $organization = $threat_data['organization'] ?? '';
            
            // If as_number contains both number and name (e.g., "AS5769 Videotron Ltee")
            $as_info = $this->parse_as_info($as_number_raw);
            
            // Use organization if available, otherwise use parsed name from as_number
            $as_name = !empty($organization) ? $organization : ($as_info['name'] ?? '');
            
            return [
                'country_code' => $threat_data['country_code'] ?? '',
                'as_number' => $as_info['number'] ?? $as_number_raw,
                'as_name' => $as_name,
            ];
        }
        
        // Check existing logs for this IP's metadata (reuse from previous entries)
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Performance optimization
        $existing_log = $wpdb->get_row($wpdb->prepare(
            "SELECT country_code, as_number, as_name 
             FROM {$this->table} 
             WHERE ip = %s 
               AND (country_code != '' OR as_number != '')
             ORDER BY id DESC 
             LIMIT 1",
            $ip
        ), ARRAY_A);
        
        if ($existing_log && (!empty($existing_log['country_code']) || !empty($existing_log['as_number']))) {
            $metadata = [
                'country_code' => $existing_log['country_code'] ?? '',
                'as_number' => $existing_log['as_number'] ?? '',
                'as_name' => $existing_log['as_name'] ?? '',
            ];
            
            // Cache the result for future requests in this session
            $cache_key = 'ip_metadata_' . md5($ip);
            wp_cache_set($cache_key, $metadata, 'vietshield_ip_metadata', 3600);
            
            return $metadata;
        }
        
        // Check transient cache
        $cache_key = 'ip_metadata_' . md5($ip);
        $cached = wp_cache_get($cache_key, 'vietshield_ip_metadata');
        
        if ($cached !== false) {
            return $cached;
        }
        
        // If not triggering remote fetch, return empty (prevents slow page loads)
        if (!$fetch_remote) {
            return [
                'country_code' => '',
                'as_number' => '',
                'as_name' => '',
            ];
        }
        
        // Fallback to external API (ip-api.com)
        // Call API
        $api_url = 'http://ip-api.com/json/' . urlencode($ip) . '?fields=status,countryCode,as';
        $response = wp_remote_get($api_url, [
            'timeout' => 5,
            'sslverify' => false,
        ]);
        
        $metadata = [
            'country_code' => '',
            'as_number' => '',
            'as_name' => '',
        ];
        
        if (!is_wp_error($response)) {
            $code = wp_remote_retrieve_response_code($response);
            if ($code === 200) {
                $body = wp_remote_retrieve_body($response);
                $data = json_decode($body, true);
                
                if (!empty($data['status']) && $data['status'] === 'success') {
                    $metadata['country_code'] = $data['countryCode'] ?? '';
                    
                    // Parse AS info from "AS5769 Videotron Ltee" format
                    if (!empty($data['as'])) {
                        $as_info = $this->parse_as_info($data['as']);
                        $metadata['as_number'] = $as_info['number'] ?? '';
                        $metadata['as_name'] = $as_info['name'] ?? '';
                    }
                }
            }
        }
        
        // Cache for 24 hours
        wp_cache_set($cache_key, $metadata, 'vietshield_ip_metadata', DAY_IN_SECONDS);
        
        return $metadata;
    }
    
    /**
     * Parse AS information from "AS5769 Videotron Ltee" format
     * 
     * @param string $as_string AS string from API
     * @return array
     */
    private function parse_as_info($as_string) {
        if (empty($as_string)) {
            return ['number' => '', 'name' => ''];
        }
        
        // Format: "AS5769 Videotron Ltee"
        if (preg_match('/^AS(\d+)\s+(.+)$/i', $as_string, $matches)) {
            return [
                'number' => 'AS' . $matches[1],
                'name' => trim($matches[2]),
            ];
        }
        
        // If already just AS number
        if (preg_match('/^AS(\d+)$/i', $as_string, $matches)) {
            return [
                'number' => 'AS' . $matches[1],
                'name' => '',
            ];
        }
        
        return ['number' => '', 'name' => ''];
    }
    
    /**
     * Get statistics
     * 
     * @param int $days Number of days
     * @return array
     */
    public function get_stats($days = 7) {
        global $wpdb;
        
        // Use the correct schema: 'date' and 'hour' columns
        $results = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$this->stats_table} 
             WHERE date >= DATE_SUB(CURDATE(), INTERVAL %d DAY)
             ORDER BY date DESC, hour DESC",
            $days
        ), ARRAY_A);
        
        // Calculate totals from hourly stats
        $totals = [
            'total_requests' => 0,
            'blocked' => 0,
            'rate_limited' => 0,
            'threat_intel' => 0,
            'sqli' => 0,
            'xss' => 0,
            'rce' => 0,
            'lfi' => 0,
            'bad_bot' => 0,
        ];
        
        // Group by date for daily stats
        $daily_stats = [];
        foreach ($results as $row) {
            $date = $row['date'];
            if (!isset($daily_stats[$date])) {
                $daily_stats[$date] = [
                    'date' => $date,
                    'total_requests' => 0,
                    'blocked' => 0,
                    'rate_limited' => 0,
                    'threat_intel' => 0,
                    'sqli' => 0,
                    'xss' => 0,
                    'rce' => 0,
                    'lfi' => 0,
                    'bad_bot' => 0,
                ];
            }
            
            // Aggregate hourly stats into daily
            foreach ($totals as $key => $value) {
                if (isset($row[$key])) {
                    $daily_stats[$date][$key] += (int) $row[$key];
                    $totals[$key] += (int) $row[$key];
                }
            }
        }
        
        // Convert to indexed array
        $daily = array_values($daily_stats);
        
        return [
            'daily' => $daily,
            'totals' => $totals,
        ];
    }
    
    /**
     * Get top blocked IPs
     * 
     * @param int $limit
     * @param int $days
     * @return array
     */
    public function get_top_blocked_ips($limit = 10, $days = 7) {
        global $wpdb;
        
        return $wpdb->get_results($wpdb->prepare(
            "SELECT ip, COUNT(*) as block_count, 
                    MAX(timestamp) as last_blocked,
                    GROUP_CONCAT(DISTINCT attack_type) as attack_types,
                    GROUP_CONCAT(DISTINCT action) as actions
             FROM {$this->table}
             WHERE action IN ('blocked', 'rate_limited')
             AND timestamp >= DATE_SUB(NOW(), INTERVAL %d DAY)
             GROUP BY ip
             ORDER BY block_count DESC
             LIMIT %d",
            $days,
            $limit
        ), ARRAY_A);
    }
    
    /**
     * Get recent attacks
     * 
     * @param int $limit
     * @return array
     */
    public function get_recent_attacks($limit = 20) {
        global $wpdb;
        
        return $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$this->table}
             WHERE action IN ('blocked', 'rate_limited')
             ORDER BY timestamp DESC
             LIMIT %d",
            $limit
        ), ARRAY_A);
    }
    
    /**
     * Cleanup old logs
     * 
     * @param int $days Days to keep
     * @return int Number of deleted rows
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
     * Get live traffic (last N seconds)
     * 
     * @param int $seconds
     * @return array
     */
    public function get_live_traffic($seconds = 60) {
        global $wpdb;
        
        return $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$this->table}
             WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %d SECOND)
             ORDER BY timestamp DESC
             LIMIT 100",
            $seconds
        ), ARRAY_A);
    }

    /**
     * Sync missing IP metadata (Country, ASN)
     * Called by cron job
     */
    public function sync_missing_metadata() {
        global $wpdb;
        
        // Find recent IPs with missing country or AS info
        // Limit to 20 IPs per run to respect API rate limits (45 req/min for ip-api.com free)
        // Check for missing country OR missing ASN info
        $ips_to_sync = $wpdb->get_col(
            "SELECT DISTINCT ip FROM {$this->table} 
             WHERE timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)
             AND (
                 country = '' OR country IS NULL
                 OR as_number = '' OR as_number IS NULL
             )
             LIMIT 20"
        );
        
        if (empty($ips_to_sync)) {
            return;
        }
        
        foreach ($ips_to_sync as $ip) {
            // Force remote fetch
            $metadata = $this->get_ip_metadata($ip, true);
            
            // If we got data, update logs and cache
            if (!empty($metadata['country_code']) || !empty($metadata['as_number'])) {
                // Update logs table
                $update_data = [];
                if (!empty($metadata['country_code'])) {
                    $update_data['country'] = $metadata['country_code'];
                    $update_data['country_code'] = $metadata['country_code'];
                }
                if (!empty($metadata['as_number'])) {
                    $update_data['as_number'] = $metadata['as_number'];
                }
                if (!empty($metadata['as_name'])) {
                    $update_data['as_name'] = $metadata['as_name'];
                }
                
                if (!empty($update_data)) {
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
                    $wpdb->update(
                        $this->table,
                        $update_data,
                        ['ip' => $ip]
                    );
                }
                
                // Update/Insert into Threat Intel table (local cache)
                $threat_table = $wpdb->prefix . 'vietshield_threat_intel';
                
                // Check if exists
                $exists = $wpdb->get_var($wpdb->prepare("SELECT id FROM {$threat_table} WHERE ip_address = %s", $ip));
                
                if ($exists) {
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
                    $wpdb->update(
                        $threat_table,
                        [
                            'country_code' => $metadata['country_code'], 
                            'as_number' => $metadata['as_number'],
                            'organization' => $metadata['as_name'],
                            'last_updated' => current_time('mysql')
                        ],
                        ['ip_address' => $ip]
                    );
                } else {
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
                    $wpdb->insert(
                        $threat_table,
                        [
                            'ip_address' => $ip,
                            'country_code' => $metadata['country_code'], 
                            'as_number' => $metadata['as_number'],
                            'organization' => $metadata['as_name'],
                            'threat_score' => 0,
                            'last_updated' => current_time('mysql')
                        ]
                    );
                }
            }
            
            // Sleep slightly to be nice to API
            usleep(200000); // 200ms
        }
    }
}
