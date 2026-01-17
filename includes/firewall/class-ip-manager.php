<?php
/**
 * IP Manager - Handle IP whitelist/blacklist
 * 
 * @package VietShield_WAF
 */

namespace VietShield\Firewall;

if (!defined('ABSPATH')) {
    exit;
}

class IPManager {
    
    /**
     * Database table name
     */
    private $table;
    
    /**
     * Cached lists
     */
    private static $cache = null;
    
    /**
     * Constructor
     */
    public function __construct() {
        global $wpdb;
        $this->table = $wpdb->prefix . 'vietshield_ip_lists';
        
        // Load cache
        if (self::$cache === null) {
            $this->load_cache();
        }
    }
    
    /**
     * Load IP lists into cache
     */
    private function load_cache() {
        global $wpdb;
        
        self::$cache = [
            'whitelist' => [],
            'blacklist' => [],
            'temporary' => [],
        ];
        
        $results = $wpdb->get_results(
            "SELECT * FROM {$this->table} 
             WHERE expires_at IS NULL OR expires_at > NOW()",
            ARRAY_A
        );
        
        foreach ($results as $row) {
            self::$cache[$row['list_type']][] = $row;
        }
    }
    
    /**
     * Check if IP is whitelisted
     * 
     * @param string $ip
     * @return bool
     */
    public function is_whitelisted($ip) {
        // Check options first (static whitelist)
        $options = get_option('vietshield_options', []);
        $static_whitelist = $options['whitelisted_ips'] ?? [];
        
        if (in_array($ip, $static_whitelist)) {
            return true;
        }
        
        // Check database
        return $this->check_list($ip, 'whitelist');
    }
    
    /**
     * Check if IP is blacklisted
     * 
     * @param string $ip
     * @return bool
     */
    public function is_blacklisted($ip) {
        // Check options first (static blacklist)
        $options = get_option('vietshield_options', []);
        $static_blacklist = $options['blacklisted_ips'] ?? [];
        
        if (in_array($ip, $static_blacklist)) {
            return true;
        }
        
        // Check database (blacklist + temporary)
        return $this->check_list($ip, 'blacklist') || $this->check_list($ip, 'temporary');
    }
    
    /**
     * Check if IP is in a specific list
     * 
     * @param string $ip
     * @param string $list_type
     * @return bool
     */
    private function check_list($ip, $list_type) {
        if (!isset(self::$cache[$list_type])) {
            return false;
        }
        
        foreach (self::$cache[$list_type] as $entry) {
            // Check ip_address - could be exact IP or CIDR range
            if (!empty($entry['ip_address'])) {
                // Check if it's a CIDR range (contains /)
                if (strpos($entry['ip_address'], '/') !== false) {
                    if ($this->ip_in_range($ip, $entry['ip_address'])) {
                        return true;
                    }
                } else {
                    // Exact IP match
                    if ($entry['ip_address'] === $ip) {
                        return true;
                    }
                }
            }
            
            // Check ip_range column (legacy/explicit CIDR)
            if (!empty($entry['ip_range']) && $this->ip_in_range($ip, $entry['ip_range'])) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Check if IP is in CIDR range
     * 
     * @param string $ip
     * @param string $range CIDR notation (e.g., 192.168.1.0/24)
     * @return bool
     */
    private function ip_in_range($ip, $range) {
        if (strpos($range, '/') === false) {
            return $ip === $range;
        }
        
        list($subnet, $bits) = explode('/', $range);
        
        // Determine IP versions
        $is_ip_v6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
        $is_subnet_v6 = filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
        
        // If versions don't match, it's not in range
        if ($is_ip_v6 !== $is_subnet_v6) {
            return false;
        }
        
        // Handle IPv6
        if ($is_ip_v6) {
            return $this->ipv6_in_range($ip, $subnet, (int) $bits);
        }
        
        // IPv4
        // Ensure bits check is valid for IPv4
        $bits = (int) $bits;
        if ($bits < 0 || $bits > 32) {
            return false;
        }
        
        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);
        $mask = -1 << (32 - $bits);
        
        $subnet_long &= $mask;
        
        return ($ip_long & $mask) === $subnet_long;
    }
    
    /**
     * Check IPv6 in range
     */
    private function ipv6_in_range($ip, $subnet, $bits) {
        $ip_bin = inet_pton($ip);
        $subnet_bin = inet_pton($subnet);
        
        if ($ip_bin === false || $subnet_bin === false) {
            return false;
        }
        
        $ip_hex = bin2hex($ip_bin);
        $subnet_hex = bin2hex($subnet_bin);
        
        // Convert bits to hex characters
        $hex_chars = ceil($bits / 4);
        
        return substr($ip_hex, 0, $hex_chars) === substr($subnet_hex, 0, $hex_chars);
    }
    
    /**
     * Add IP to whitelist
     * 
     * @param string $ip
     * @param string $reason
     * @return int|false
     */
    public function add_to_whitelist($ip, $reason = '') {
        return $this->add_to_list($ip, 'whitelist', $reason);
    }
    
    /**
     * Add IP to blacklist
     * 
     * @param string $ip
     * @param string $type 'blacklist' or 'temporary'
     * @param string $reason
     * @param int $duration Duration in seconds for temporary blocks (0 for permanent)
     * @return int|false
     */
    public function add_to_blacklist($ip, $type = 'blacklist', $reason = '', $duration = 0) {
        $expires_at = null;
        
        if ($type === 'temporary' && $duration > 0) {
            $expires_at = gmdate('Y-m-d H:i:s', time() + $duration);
        }
        
        return $this->add_to_list($ip, $type, $reason, $expires_at);
    }
    
    /**
     * Add IP to list
     */
    private function add_to_list($ip, $list_type, $reason = '', $expires_at = null) {
        global $wpdb;
        
        // Check if already exists
        $existing = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM {$this->table} 
             WHERE (ip_address = %s OR ip_range = %s) AND list_type = %s",
            $ip, $ip, $list_type
        ));
        
        if ($existing) {
            // Update existing
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
            $wpdb->update(
                $this->table,
                [
                    'reason' => $reason,
                    'expires_at' => $expires_at,
                    'hit_count' => 0,
                ],
                ['id' => $existing]
            );
            
            // Clear cache
            self::$cache = null;
            $this->load_cache();
            
            return $existing;
        }
        
        // Determine if IP or range
        $ip_address = '';
        $ip_range = '';
        
        if (strpos($ip, '/') !== false) {
            $ip_range = $ip;
        } else {
            $ip_address = $ip;
        }
        
        $result = $wpdb->insert($this->table, [
            'ip_address' => $ip_address,
            'ip_range' => $ip_range,
            'list_type' => $list_type,
            'reason' => $reason,
            'expires_at' => $expires_at,
            'created_by' => get_current_user_id(),
        ]);
        
        // Clear cache
        self::$cache = null;
        $this->load_cache();
        
        return $result ? $wpdb->insert_id : false;
    }
    
    /**
     * Remove IP from list
     * 
     * @param int $id Entry ID
     * @return bool
     */
    public function remove($id) {
        global $wpdb;
        
        $result = $wpdb->delete($this->table, ['id' => $id]);
        
        // Clear cache
        self::$cache = null;
        $this->load_cache();
        
        return $result !== false;
    }
    
    /**
     * Remove IP by address
     * 
     * @param string $ip
     * @param string $list_type Optional
     * @return bool
     */
    public function remove_ip($ip, $list_type = null) {
        global $wpdb;
        
        $where = ['ip_address' => $ip];
        if ($list_type) {
            $where['list_type'] = $list_type;
        }
        
        $result = $wpdb->delete($this->table, $where);
        
        // Also try range
        $where['ip_range'] = $ip;
        unset($where['ip_address']);
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
        $wpdb->delete($this->table, $where);
        
        // Clear cache
        self::$cache = null;
        $this->load_cache();
        
        return $result !== false;
    }
    
    /**
     * Get all IPs in a list
     * 
     * @param string $list_type
     * @return array
     */
    public function get_list($list_type) {
        global $wpdb;
        
        return $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$this->table} 
             WHERE list_type = %s 
             AND (expires_at IS NULL OR expires_at > NOW())
             ORDER BY created_at DESC",
            $list_type
        ), ARRAY_A);
    }
    
    /**
     * Increment hit count for an IP
     * 
     * @param string $ip
     */
    public function increment_hit_count($ip) {
        global $wpdb;
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
        $wpdb->query($wpdb->prepare(
            "UPDATE {$this->table} 
             SET hit_count = hit_count + 1 
             WHERE ip_address = %s OR ip_range = %s",
            $ip, $ip
        ));
    }
    
    /**
     * Cleanup expired entries
     * 
     * @return int Number of deleted entries
     */
    public function cleanup_expired() {
        global $wpdb;
        
        $deleted = $wpdb->query(
            "DELETE FROM {$this->table} 
             WHERE expires_at IS NOT NULL AND expires_at < NOW()"
        );
        
        // Clear cache
        self::$cache = null;
        $this->load_cache();
        
        return $deleted;
    }
    
    /**
     * Get IP info
     * 
     * @param string $ip
     * @return array|null
     */
    public function get_ip_info($ip) {
        global $wpdb;
        
        return $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$this->table} WHERE ip_address = %s OR ip_range = %s",
            $ip, $ip
        ), ARRAY_A);
    }
    
    /**
     * Clear cache
     */
    public static function clear_cache() {
        self::$cache = null;
    }
}
