<?php
/**
 * Rate Limiter - Prevent brute force and DDoS
 * 
 * @package VietShield_WAF
 */

namespace VietShield\Firewall;

if (!defined('ABSPATH')) {
    exit;
}

class RateLimiter {
    
    /**
     * Database table name
     */
    private $table;
    
    /**
     * Rate limit configurations
     */
    private $limits;
    
    /**
     * Constructor
     */
    public function __construct() {
        global $wpdb;
        $this->table = $wpdb->prefix . 'vietshield_rate_limits';
        
        $options = get_option('vietshield_options', []);
        
        $this->limits = [
            'global' => [
                'requests' => $options['rate_limit_global'] ?? 100,
                'window' => 60, // 1 minute
            ],
            'login' => [
                'requests' => $options['rate_limit_login'] ?? 20,
                'window' => 300, // 5 minutes
            ],
            'xmlrpc' => [
                'requests' => $options['rate_limit_xmlrpc'] ?? 20,
                'window' => 60,
            ],
            'api' => [
                'requests' => 60,
                'window' => 60,
            ],
            '404' => [
                'requests' => 20,
                'window' => 60,
            ],
        ];
    }
    
    /**
     * Check rate limit for request
     * 
     * @param string $ip Client IP
     * @param array $request_data Request data
     * @return array ['blocked' => bool, 'reason' => string]
     */
    public function check($ip, $request_data) {
        // Skip static files - don't count towards rate limit
        if ($this->is_static_file($request_data['uri'] ?? '')) {
            return [
                'blocked' => false,
                'reason' => '',
                'skipped' => true,
            ];
        }
        
        // Determine endpoint type
        $endpoint = $this->get_endpoint_type($request_data);
        
        // Get limit config
        $limit_config = $this->limits[$endpoint] ?? $this->limits['global'];
        
        // Check rate limit
        $current_count = $this->get_request_count($ip, $endpoint);
        
        if ($current_count >= $limit_config['requests']) {
            return [
                'blocked' => true,
                'reason' => sprintf(
                    'Rate limit exceeded: %d requests in %d seconds for %s',
                    $limit_config['requests'],
                    $limit_config['window'],
                    $endpoint
                ),
                'endpoint' => $endpoint,
                'current_count' => $current_count + 1, // +1 for this request
                'limit' => $limit_config['requests'],
                'window' => $limit_config['window'],
                'retry_after' => $this->get_retry_after($ip, $endpoint, $limit_config['window']),
            ];
        }
        
        // Increment counter
        $this->increment_count($ip, $endpoint, $limit_config['window']);
        
        return [
            'blocked' => false,
            'reason' => '',
            'remaining' => $limit_config['requests'] - $current_count - 1,
        ];
    }
    
    /**
     * Check if request is for a static file
     * 
     * @param string $uri Request URI
     * @return bool
     */
    private function is_static_file($uri) {
        // Remove query string
        $path = wp_parse_url($uri, PHP_URL_PATH);
        if (!$path) {
            return false;
        }
        
        // Get file extension
        $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        
        // List of static file extensions to exclude from rate limiting
        $static_extensions = [
            // Stylesheets
            'css', 'less', 'scss', 'sass',
            // JavaScript
            'js', 'mjs', 'jsx', 'ts', 'tsx',
            // Images
            'jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'ico', 'bmp', 'tiff', 'avif',
            // Fonts
            'woff', 'woff2', 'ttf', 'otf', 'eot',
            // Media
            'mp3', 'mp4', 'webm', 'ogg', 'wav', 'avi', 'mov', 'wmv', 'flv',
            // Documents (usually cached)
            'pdf',
            // Maps
            'map',
        ];
        
        return in_array($extension, $static_extensions);
    }
    
    /**
     * Determine endpoint type from request
     */
    private function get_endpoint_type($request_data) {
        $uri = $request_data['uri'] ?? '';
        
        // Login page
        if ($request_data['is_login'] ?? false) {
            return 'login';
        }
        
        // XML-RPC
        if ($request_data['is_xmlrpc'] ?? false) {
            return 'xmlrpc';
        }
        
        // REST API
        if ($request_data['is_rest'] ?? false) {
            return 'api';
        }
        
        // wp-admin AJAX
        if (strpos($uri, 'admin-ajax.php') !== false) {
            return 'api';
        }
        
        return 'global';
    }
    
    /**
     * Get current request count
     */
    private function get_request_count($ip, $endpoint) {
        global $wpdb;
        
        $window_start = time() - ($this->limits[$endpoint]['window'] ?? 60);
        
        $count = $wpdb->get_var($wpdb->prepare(
            "SELECT request_count FROM {$this->table} 
             WHERE ip = %s AND endpoint = %s AND window_start > %d",
            $ip,
            $endpoint,
            $window_start
        ));
        
        return (int) $count;
    }
    
    /**
     * Increment request count
     */
    private function increment_count($ip, $endpoint, $window) {
        global $wpdb;
        
        $current_time = time();
        $window_start = $current_time - $window;
        
        // Try to update existing record
        $updated = $wpdb->query($wpdb->prepare(
            "UPDATE {$this->table} 
             SET request_count = request_count + 1 
             WHERE ip = %s AND endpoint = %s AND window_start > %d",
            $ip,
            $endpoint,
            $window_start
        ));
        
        if (!$updated) {
            // Insert new record
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
            $wpdb->query($wpdb->prepare(
                "INSERT INTO {$this->table} (ip, endpoint, request_count, window_start) 
                 VALUES (%s, %s, 1, %d)
                 ON DUPLICATE KEY UPDATE request_count = request_count + 1, window_start = %d",
                $ip,
                $endpoint,
                $current_time,
                $current_time
            ));
        }
    }
    
    /**
     * Get seconds until rate limit resets
     */
    private function get_retry_after($ip, $endpoint, $window) {
        global $wpdb;
        
        $oldest_window = $wpdb->get_var($wpdb->prepare(
            "SELECT MIN(window_start) FROM {$this->table} 
             WHERE ip = %s AND endpoint = %s",
            $ip,
            $endpoint
        ));
        
        if ($oldest_window) {
            $reset_time = (int) $oldest_window + $window;
            return max(0, $reset_time - time());
        }
        
        return $window;
    }
    
    /**
     * Reset rate limit for IP
     */
    public function reset($ip, $endpoint = null) {
        global $wpdb;
        
        if ($endpoint) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
            $wpdb->delete($this->table, [
                'ip' => $ip,
                'endpoint' => $endpoint,
            ]);
        } else {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
            $wpdb->delete($this->table, ['ip' => $ip]);
        }
    }
    
    /**
     * Cleanup old rate limit entries
     */
    public function cleanup() {
        global $wpdb;
        
        // Remove entries older than max window (5 minutes)
        $max_window = 300;
        $cutoff = time() - $max_window;
        
        return $wpdb->query($wpdb->prepare(
            "DELETE FROM {$this->table} WHERE window_start < %d",
            $cutoff
        ));
    }
    
    /**
     * Get rate limit status for IP
     */
    public function get_status($ip) {
        global $wpdb;
        
        $results = $wpdb->get_results($wpdb->prepare(
            "SELECT endpoint, request_count, window_start FROM {$this->table} WHERE ip = %s",
            $ip
        ), ARRAY_A);
        
        $status = [];
        
        foreach ($results as $row) {
            $endpoint = $row['endpoint'];
            $limit_config = $this->limits[$endpoint] ?? $this->limits['global'];
            
            $status[$endpoint] = [
                'count' => (int) $row['request_count'],
                'limit' => $limit_config['requests'],
                'window' => $limit_config['window'],
                'remaining' => max(0, $limit_config['requests'] - $row['request_count']),
                'reset_at' => (int) $row['window_start'] + $limit_config['window'],
            ];
        }
        
        return $status;
    }
    
    /**
     * Check if specific limit is exceeded
     */
    public function is_limit_exceeded($ip, $endpoint) {
        $count = $this->get_request_count($ip, $endpoint);
        $limit = $this->limits[$endpoint]['requests'] ?? $this->limits['global']['requests'];
        
        return $count >= $limit;
    }
    
    /**
     * Add custom rate limit
     */
    public function add_custom_limit($endpoint, $requests, $window) {
        $this->limits[$endpoint] = [
            'requests' => $requests,
            'window' => $window,
        ];
    }
    
    /**
     * Get all configured limits
     */
    public function get_limits() {
        return $this->limits;
    }
}
