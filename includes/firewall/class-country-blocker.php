<?php
/**
 * Country Blocker - Block requests by country
 * 
 * @package VietShield_WAF
 */

namespace VietShield\Firewall;

if (!defined('ABSPATH')) {
    exit;
}

class CountryBlocker {
    
    /**
     * GeoLocator instance
     */
    private $geo_locator;
    
    /**
     * Plugin options
     */
    private $options;
    
    /**
     * Constructor
     */
    public function __construct() {
        // Load GeoLocator if not already loaded
        if (!class_exists('VietShield\Firewall\GeoLocator')) {
            require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-geo-locator.php';
        }
        $this->geo_locator = new \VietShield\Firewall\GeoLocator();
        $this->options = get_option('vietshield_options', []);
    }
    
    /**
     * Check if IP's country should be blocked
     * 
     * @param string $ip IP address
     * @return array ['blocked' => bool, 'country' => string, 'reason' => string]
     */
    public function check($ip) {
        // Check if country blocking is enabled
        if (!$this->get_option('country_blocking_enabled', false)) {
            return [
                'blocked' => false,
                'country' => null,
                'reason' => '',
            ];
        }
        
        // Get country from IP
        $country = $this->geo_locator->get_country($ip);
        
        if (!$country) {
            // If we can't determine country, allow by default (or block if configured)
            $block_unknown = $this->get_option('block_unknown_countries', false);
            return [
                'blocked' => $block_unknown,
                'country' => null,
                'reason' => $block_unknown ? 'Country could not be determined' : '',
            ];
        }
        
        // Get blocked countries list
        $blocked_countries = $this->get_option('blocked_countries', []);
        
        if (empty($blocked_countries) || !is_array($blocked_countries)) {
            return [
                'blocked' => false,
                'country' => $country,
                'reason' => '',
            ];
        }
        
        // Check if country is in blocked list
        if (in_array($country, $blocked_countries)) {
            return [
                'blocked' => true,
                'country' => $country,
                'reason' => 'Country ' . $country . ' is blocked',
            ];
        }
        
        return [
            'blocked' => false,
            'country' => $country,
            'reason' => '',
        ];
    }
    
    /**
     * Get country for IP (for logging)
     * 
     * @param string $ip
     * @return string|false
     */
    public function get_country($ip) {
        return $this->geo_locator->get_country($ip);
    }
    
    /**
     * Get country name from code
     * 
     * @param string $code
     * @return string
     */
    public function get_country_name($code) {
        return $this->geo_locator->get_country_name($code);
    }
    
    /**
     * Get all countries list
     * 
     * @return array
     */
    public function get_countries_list() {
        return $this->geo_locator->get_countries_list();
    }
    
    /**
     * Get statistics by country
     * 
     * @param int $days Number of days
     * @return array
     */
    public function get_country_stats($days = 7) {
        global $wpdb;
        
        $table = $wpdb->prefix . 'vietshield_logs';
        
        $results = $wpdb->get_results($wpdb->prepare(
            "SELECT country, 
                    COUNT(*) as total_requests,
                    SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) as blocked_requests,
                    SUM(CASE WHEN attack_type = 'sqli' THEN 1 ELSE 0 END) as sqli_attacks,
                    SUM(CASE WHEN attack_type = 'xss' THEN 1 ELSE 0 END) as xss_attacks
             FROM {$table}
             WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %d DAY)
             AND country != ''
             GROUP BY country
             ORDER BY blocked_requests DESC
             LIMIT 50",
            $days
        ), ARRAY_A);
        
        return $results;
    }
    
    /**
     * Get option with default
     */
    private function get_option($key, $default = null) {
        return $this->options[$key] ?? $default;
    }
}
