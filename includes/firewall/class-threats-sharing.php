<?php
/**
 * Threats Sharing
 * 
 * Automatically submits blocked IPs to VietShield Intelligence API for community sharing.
 * This feature is always enabled and cannot be disabled.
 *
 * @package VietShield_WAF
 */

namespace VietShield\Firewall;

if (!defined('ABSPATH')) {
    exit;
}

class ThreatsSharing {
    
    const API_URL = 'https://intelligence.vietshield.org/api/submit.php';
    const API_KEY = 'To2xwnzQrzDsh8y1Usr1Sw90U14ieJGe';
    const QUEUE_TABLE = 'vietshield_threats_queue';
    const BATCH_SIZE = 50; // Submit up to 50 IPs per batch
    const MAX_RETRIES = 3;
    
    /**
     * Queue an IP for submission
     * 
     * @param string $ip IP address
     * @param string $reason Reason for blocking
     * @param string $attack_type Attack type (sqli, xss, rce, etc.)
     * @param string $severity Severity level
     * @param array $metadata Additional metadata (country_code, as_number, organization)
     */
    public static function queue_ip($ip, $reason = '', $attack_type = '', $severity = 'medium', $metadata = []) {
        global $wpdb;
        
        // Validate IP
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        
        // Skip private/local IPs
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return false;
        }
        
        $table = $wpdb->prefix . self::QUEUE_TABLE;
        
        // Check if table exists, create if not
        self::ensure_table_exists();
        
        // Check if IP already queued (not submitted yet)
        $existing = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM $table WHERE ip = %s AND submitted = 0 LIMIT 1",
            $ip
        ));
        
        if ($existing) {
            // Update existing queue entry with latest data
            $wpdb->update(
                $table,
                [
                    'reason' => $reason,
                    'attack_type' => $attack_type,
                    'severity' => $severity,
                    'country_code' => $metadata['country_code'] ?? '',
                    'as_number' => $metadata['as_number'] ?? '',
                    'organization' => $metadata['organization'] ?? '',
                    'updated_at' => current_time('mysql')
                ],
                ['id' => $existing],
                ['%s', '%s', '%s', '%s', '%s', '%s', '%s'],
                ['%d']
            );
            return true;
        }
        
        // Insert new queue entry
        $result = $wpdb->insert(
            $table,
            [
                'ip' => $ip,
                'reason' => $reason,
                'attack_type' => $attack_type,
                'severity' => $severity,
                'country_code' => $metadata['country_code'] ?? '',
                'as_number' => $metadata['as_number'] ?? '',
                'organization' => $metadata['organization'] ?? '',
                'domain' => self::get_domain(),
                'submitted' => 0,
                'retries' => 0,
                'created_at' => current_time('mysql'),
                'updated_at' => current_time('mysql')
            ],
            ['%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%d', '%s', '%s']
        );
        
        return $result !== false;
    }
    
    /**
     * Submit queued IPs to Intelligence API
     * 
     * @param int $limit Maximum number of IPs to submit in this batch
     * @return array Submission results
     */
    public static function submit_queue($limit = null) {
        global $wpdb;
        
        $table = $wpdb->prefix . self::QUEUE_TABLE;
        
        // Ensure table exists
        if (!self::table_exists($table)) {
            return ['success' => false, 'message' => 'Queue table does not exist'];
        }
        
        $limit = $limit ?? self::BATCH_SIZE;
        
        // Get pending IPs (not submitted, retries < MAX_RETRIES)
        $pending = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM $table 
             WHERE submitted = 0 AND retries < %d 
             ORDER BY created_at ASC 
             LIMIT %d",
            self::MAX_RETRIES,
            $limit
        ), ARRAY_A);
        
        if (empty($pending)) {
            return ['success' => true, 'message' => 'No pending IPs to submit', 'submitted' => 0];
        }
        
        // Prepare batch data
        $ips_to_submit = [];
        $ips_for_lookup = [];
        
        foreach ($pending as $key => $item) {
            // Check if metadata is missing
            if (empty($item['country_code']) || empty($item['as_number']) || empty($item['organization'])) {
                $ips_for_lookup[] = $item['ip'];
            }
        }
        
        // Enrich metadata if needed
        $metadata_map = [];
        if (!empty($ips_for_lookup)) {
            $metadata_map = self::fetch_ip_metadata($ips_for_lookup);
        }
        
        foreach ($pending as $item) {
            // Merge enriched metadata if available
            if (isset($metadata_map[$item['ip']])) {
                $meta = $metadata_map[$item['ip']];
                $item['country_code'] = $item['country_code'] ?: ($meta['countryCode'] ?? null);
                $item['as_number'] = $item['as_number'] ?: ($meta['as'] ?? null); // ip-api returns 'as' e.g. "AS12345 Name"
                $item['organization'] = $item['organization'] ?: ($meta['org'] ?? null);
                
                // Update DB with enriched data so we don't lookup again on retry
                $wpdb->update(
                    $table,
                    [
                        'country_code' => $item['country_code'],
                        'as_number' => $item['as_number'],
                        'organization' => $item['organization']
                    ],
                    ['id' => $item['id']],
                    ['%s', '%s', '%s'],
                    ['%d']
                );
            }
            
            // Format reason
            $reason = $item['reason'];
            // Handle specific case where reason is explicitly "(empty)" string
            if ($reason === '(empty)') {
                $reason = '';
            }
            
            $attack_type = $item['attack_type'];
            
            if (!empty($attack_type)) {
                $readable_type = strtoupper($attack_type); // e.g. SQLI, XSS
                
                if (empty($reason)) {
                    $reason = "$readable_type attack detected";
                } else {
                    $reason = "$readable_type: $reason";
                }
            } elseif (empty($reason)) {
                $reason = 'Malicious activity detected';
            }
            
            $ips_to_submit[] = [
                'ip' => $item['ip'],
                'domain' => $item['domain'] ?: self::get_domain(),
                'reason' => $reason,
                'type' => $attack_type,
                // Removed category as requested
                'country_code' => !empty($item['country_code']) ? $item['country_code'] : null,
                'as_number' => !empty($item['as_number']) ? $item['as_number'] : null,
                'organization' => !empty($item['organization']) ? $item['organization'] : null,
            ];
        }
        
        // Submit to API
        $result = self::submit_to_api($ips_to_submit);
        
        // Update queue based on result
        $submitted_count = 0;
        $failed_count = 0;
        
        if ($result['success']) {
            $successful_ips = [];
            if (isset($result['results']['success'])) {
                foreach ($result['results']['success'] as $success_item) {
                    $successful_ips[] = $success_item['ip'];
                }
            }
            
            foreach ($pending as $item) {
                if (in_array($item['ip'], $successful_ips)) {
                    // Mark as submitted
                    $wpdb->update(
                        $table,
                        [
                            'submitted' => 1,
                            'submitted_at' => current_time('mysql'),
                            'updated_at' => current_time('mysql')
                        ],
                        ['id' => $item['id']],
                        ['%d', '%s', '%s'],
                        ['%d']
                    );
                    $submitted_count++;
                } else {
                    // Increment retry count
                    $wpdb->update(
                        $table,
                        [
                            'retries' => $item['retries'] + 1,
                            'updated_at' => current_time('mysql')
                        ],
                        ['id' => $item['id']],
                        ['%d', '%s'],
                        ['%d']
                    );
                    $failed_count++;
                }
            }
        } else {
            // All failed - increment retry count
            foreach ($pending as $item) {
                $wpdb->update(
                    $table,
                    [
                        'retries' => $item['retries'] + 1,
                        'updated_at' => current_time('mysql')
                    ],
                    ['id' => $item['id']],
                    ['%d', '%s'],
                    ['%d']
                );
            }
            $failed_count = count($pending);
        }
        
        return [
            'success' => $result['success'],
            'submitted' => $submitted_count,
            'failed' => $failed_count,
            'total' => count($pending),
            'message' => $result['message'] ?? ''
        ];
    }
    
    /**
     * Fetch metadata for IP batch
     */
    private static function fetch_ip_metadata($ips) {
        if (empty($ips)) return [];
        
        // Chunk IPs to max 100 per request (API limit)
        $chunks = array_chunk($ips, 100);
        $results = [];
        
        foreach ($chunks as $chunk) {
            $response = wp_remote_post('http://ip-api.com/batch?fields=query,status,countryCode,org,as', [
                'body' => json_encode($chunk),
                'timeout' => 10,
                'sslverify' => false
            ]);
            
            if (!is_wp_error($response)) {
                $body = wp_remote_retrieve_body($response);
                $data = json_decode($body, true);
                if (is_array($data)) {
                    foreach ($data as $entry) {
                        if (isset($entry['query']) && isset($entry['status']) && $entry['status'] === 'success') {
                            $results[$entry['query']] = $entry;
                        }
                    }
                }
            }
        }
        
        return $results;
    }
    
    /**
     * Submit IPs to Intelligence API
     * 
     * @param array $ips Array of IP data
     * @return array API response
     */
    private static function submit_to_api($ips) {
        if (empty($ips)) {
            return ['success' => false, 'message' => 'No IPs to submit'];
        }
        
        // Prepare request data
        $data = [
            'api_key' => self::API_KEY,
            'domain' => self::get_domain(),
        ];
        
        // Use batch format if multiple IPs
        if (count($ips) > 1) {
            $data['ips'] = $ips;
        } else {
            // Single IP format
            $ip_data = $ips[0];
            $data['ip'] = $ip_data['ip'];
            $data['reason'] = $ip_data['reason'] ?? '';
            $data['type'] = $ip_data['type'] ?? '';
            // Removed category
            $data['country_code'] = $ip_data['country_code'] ?? null;
            $data['as_number'] = $ip_data['as_number'] ?? null;
            $data['organization'] = $ip_data['organization'] ?? null;
        }
        
        // Make API request
        $response = wp_remote_post(self::API_URL, [
            'headers' => [
                'Content-Type' => 'application/json',
            ],
            'body' => json_encode($data),
            'timeout' => 30,
            'sslverify' => true,
        ]);
        
        if (is_wp_error($response)) {
            error_log('VietShield Threats Sharing API Error: ' . $response->get_error_message());
            return [
                'success' => false,
                'message' => $response->get_error_message()
            ];
        }
        
        $status_code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        $result = json_decode($body, true);
        
        if ($status_code === 200 && isset($result['success']) && $result['success']) {
            return [
                'success' => true,
                'message' => $result['message'] ?? 'IPs submitted successfully',
                'results' => $result['results'] ?? []
            ];
        }
        
        // Handle error response
        $error_message = $result['error'] ?? 'Unknown error';
        error_log('VietShield Threats Sharing API Error: ' . $error_message);
        
        return [
            'success' => false,
            'message' => $error_message
        ];
    }
    
    /**
     * Get current domain
     */
    private static function get_domain() {
        $domain = parse_url(home_url(), PHP_URL_HOST);
        return $domain ?: '';
    }
    
    /**
     * Get queue statistics
     */
    public static function get_stats() {
        global $wpdb;
        
        $table = $wpdb->prefix . self::QUEUE_TABLE;
        
        if (!self::table_exists($table)) {
            return [
                'pending' => 0,
                'submitted' => 0,
                'failed' => 0,
                'last_submission' => null
            ];
        }
        
        $pending = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table WHERE submitted = 0");
        $submitted = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table WHERE submitted = 1");
        $failed = (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $table WHERE submitted = 0 AND retries >= %d",
            self::MAX_RETRIES
        ));
        
        $last_submission = $wpdb->get_var(
            "SELECT submitted_at FROM $table WHERE submitted = 1 ORDER BY submitted_at DESC LIMIT 1"
        );
        
        return [
            'pending' => $pending,
            'submitted' => $submitted,
            'failed' => $failed,
            'last_submission' => $last_submission
        ];
    }
    
    /**
     * Ensure queue table exists
     */
    private static function ensure_table_exists() {
        global $wpdb;
        
        $table = $wpdb->prefix . self::QUEUE_TABLE;
        
        if (self::table_exists($table)) {
            return;
        }
        
        $charset_collate = $wpdb->get_charset_collate();
        
        $sql = "CREATE TABLE IF NOT EXISTS $table (
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
        dbDelta($sql);
    }
    
    /**
     * Check if table exists
     */
    private static function table_exists($table) {
        global $wpdb;
        return $wpdb->get_var("SHOW TABLES LIKE '$table'") === $table;
    }
    
    /**
     * Clean up old submitted entries (older than 30 days)
     */
    public static function cleanup_old_entries() {
        global $wpdb;
        
        $table = $wpdb->prefix . self::QUEUE_TABLE;
        
        if (!self::table_exists($table)) {
            return;
        }
        
        // Delete submitted entries older than 30 days
        $wpdb->query(
            "DELETE FROM $table 
             WHERE submitted = 1 
             AND submitted_at < DATE_SUB(NOW(), INTERVAL 30 DAY)"
        );
    }
}
