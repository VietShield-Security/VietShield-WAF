<?php
/**
 * Cloudflare Integration - Trusted Proxy handling
 * 
 * @package VietShield_WAF
 */

namespace VietShield\Firewall;

if (!defined('ABSPATH')) {
    exit;
}

class CloudflareIntegration {
    
    /**
     * Cloudflare IP ranges cache option name
     */
    const CACHE_OPTION = 'vietshield_cloudflare_ips';
    
    /**
     * Cloudflare IP endpoints
     */
    private static $cloudflare_urls = [
        'ipv4' => 'https://www.cloudflare.com/ips-v4/',
        'ipv6' => 'https://www.cloudflare.com/ips-v6/',
    ];
    
    /**
     * Cached Cloudflare IPs
     */
    private static $cloudflare_ips = null;
    
    /**
     * Check if request is coming from Cloudflare
     * 
     * @return bool
     */
    public static function is_cloudflare_request() {
        // Check for CF-Connecting-IP header (only Cloudflare sends this)
        if (empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            return false;
        }
        
        // Verify REMOTE_ADDR is a Cloudflare IP
        $remote_addr = $_SERVER['REMOTE_ADDR'] ?? '';
        return self::is_cloudflare_ip($remote_addr);
    }
    
    /**
     * Check if IP is a Cloudflare IP
     * 
     * @param string $ip
     * @return bool
     */
    public static function is_cloudflare_ip($ip) {
        if (empty($ip)) {
            return false;
        }
        
        $cf_ips = self::get_cloudflare_ips();
        
        foreach ($cf_ips as $range) {
            if (self::ip_in_range($ip, $range)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Get real client IP (handles Cloudflare proxy)
     * 
     * @return string
     */
    public static function get_real_ip() {
        $options = get_option('vietshield_options', []);
        
        // If Cloudflare trusted proxy is enabled
        if (!empty($options['trust_cloudflare_proxy'])) {
            if (self::is_cloudflare_request()) {
                // Trust CF-Connecting-IP header
                $cf_ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? '';
                if (filter_var($cf_ip, FILTER_VALIDATE_IP)) {
                    return $cf_ip;
                }
            }
        }
        
        // Fallback to standard headers
        $headers = [
            'HTTP_X_REAL_IP',            // Nginx proxy
            'HTTP_X_FORWARDED_FOR',      // Standard proxy
            'HTTP_CLIENT_IP',
            'REMOTE_ADDR'
        ];
        
        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = $_SERVER[$header];
                
                // X-Forwarded-For can contain multiple IPs
                if ($header === 'HTTP_X_FORWARDED_FOR') {
                    $ips = explode(',', $ip);
                    $ip = trim($ips[0]);
                }
                
                // Validate IP
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
    
    /**
     * Get Cloudflare IP ranges
     * 
     * @return array
     */
    public static function get_cloudflare_ips() {
        if (self::$cloudflare_ips !== null) {
            return self::$cloudflare_ips;
        }
        
        // Try cache first
        $cached = get_option(self::CACHE_OPTION, []);
        if (!empty($cached['ips']) && !empty($cached['expires']) && $cached['expires'] > time()) {
            self::$cloudflare_ips = $cached['ips'];
            return self::$cloudflare_ips;
        }
        
        // Fallback to hardcoded list (updated Jan 2025)
        self::$cloudflare_ips = self::get_fallback_ips();
        
        return self::$cloudflare_ips;
    }
    
    /**
     * Sync Cloudflare IP ranges from their API
     * 
     * @return array
     */
    public static function sync_cloudflare_ips() {
        $all_ips = [];
        
        foreach (self::$cloudflare_urls as $type => $url) {
            $response = wp_remote_get($url, [
                'timeout' => 30,
                'sslverify' => true,
            ]);
            
            if (is_wp_error($response)) {
                error_log("VietShield: Failed to fetch Cloudflare IPs from {$url}: " . $response->get_error_message());
                continue;
            }
            
            $body = wp_remote_retrieve_body($response);
            $lines = explode("\n", trim($body));
            
            foreach ($lines as $line) {
                $ip = trim($line);
                if (!empty($ip) && (strpos($ip, '/') !== false || filter_var($ip, FILTER_VALIDATE_IP))) {
                    $all_ips[] = $ip;
                }
            }
        }
        
        if (empty($all_ips)) {
            return ['success' => false, 'count' => 0, 'error' => 'No IPs found'];
        }
        
        $all_ips = array_unique($all_ips);
        
        // Cache for 24 hours
        update_option(self::CACHE_OPTION, [
            'ips' => $all_ips,
            'expires' => time() + DAY_IN_SECONDS,
            'synced_at' => current_time('mysql'),
        ]);
        
        // Clear static cache
        self::$cloudflare_ips = $all_ips;
        
        error_log("VietShield: Synced " . count($all_ips) . " Cloudflare IP ranges");
        
        return ['success' => true, 'count' => count($all_ips)];
    }
    
    /**
     * Get sync status
     * 
     * @return array
     */
    public static function get_sync_status() {
        $cached = get_option(self::CACHE_OPTION, []);
        
        return [
            'count' => count($cached['ips'] ?? []),
            'synced_at' => $cached['synced_at'] ?? null,
            'expires' => !empty($cached['expires']) ? date('Y-m-d H:i:s', $cached['expires']) : null,
        ];
    }
    
    /**
     * Check if IP is in CIDR range
     * 
     * @param string $ip
     * @param string $range
     * @return bool
     */
    private static function ip_in_range($ip, $range) {
        if (strpos($range, '/') === false) {
            return $ip === $range;
        }
        
        list($subnet, $bits) = explode('/', $range);
        
        // Handle IPv6
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return self::ipv6_in_range($ip, $subnet, (int) $bits);
        }
        
        // IPv4
        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);
        
        if ($ip_long === false || $subnet_long === false) {
            return false;
        }
        
        $mask = -1 << (32 - (int) $bits);
        $subnet_long &= $mask;
        
        return ($ip_long & $mask) === $subnet_long;
    }
    
    /**
     * Check IPv6 in range
     */
    private static function ipv6_in_range($ip, $subnet, $bits) {
        $ip_bin = @inet_pton($ip);
        $subnet_bin = @inet_pton($subnet);
        
        if ($ip_bin === false || $subnet_bin === false) {
            return false;
        }
        
        $ip_hex = bin2hex($ip_bin);
        $subnet_hex = bin2hex($subnet_bin);
        
        $hex_chars = (int) ceil($bits / 4);
        
        return substr($ip_hex, 0, $hex_chars) === substr($subnet_hex, 0, $hex_chars);
    }
    
    /**
     * Fallback Cloudflare IPs (hardcoded, updated Jan 2025)
     * 
     * @return array
     */
    private static function get_fallback_ips() {
        return [
            // IPv4
            '173.245.48.0/20',
            '103.21.244.0/22',
            '103.22.200.0/22',
            '103.31.4.0/22',
            '141.101.64.0/18',
            '108.162.192.0/18',
            '190.93.240.0/20',
            '188.114.96.0/20',
            '197.234.240.0/22',
            '198.41.128.0/17',
            '162.158.0.0/15',
            '104.16.0.0/13',
            '104.24.0.0/14',
            '172.64.0.0/13',
            '131.0.72.0/22',
            // IPv6
            '2400:cb00::/32',
            '2606:4700::/32',
            '2803:f800::/32',
            '2405:b500::/32',
            '2405:8100::/32',
            '2a06:98c0::/29',
            '2c0f:f248::/32',
        ];
    }
}
