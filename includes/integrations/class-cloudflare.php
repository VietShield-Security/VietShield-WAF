<?php
/**
 * Cloudflare Integration
 *
 * @package VietShield_WAF
 */

namespace VietShield\Integrations;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class Cloudflare
 */
class Cloudflare {

    /**
     * Cloudflare IP URLs
     */
    const IPV4_URL = 'https://www.cloudflare.com/ips-v4';
    const IPV6_URL = 'https://www.cloudflare.com/ips-v6';

    /**
     * Cache key
     */
    const CACHE_KEY = 'vietshield_cloudflare_ips';

    /**
     * Cache expiry (24 hours)
     */
    const CACHE_EXPIRY = 86400;

    /**
     * Get Cloudflare IP ranges
     *
     * @param bool $force_refresh Whether to force refresh from remote
     * @return array List of IP ranges (IPv4 and IPv6)
     */
    public function get_ip_ranges($force_refresh = false) {
        if (!$force_refresh) {
            $cached = get_transient(self::CACHE_KEY);
            if ($cached !== false && is_array($cached)) {
                return $cached;
            }
        }

        $ips = [];

        // Fetch IPv4
        $ipv4 = $this->fetch_ips(self::IPV4_URL);
        if (!empty($ipv4)) {
            $ips = array_merge($ips, $ipv4);
        }

        // Fetch IPv6
        $ipv6 = $this->fetch_ips(self::IPV6_URL);
        if (!empty($ipv6)) {
            $ips = array_merge($ips, $ipv6);
        }

        // If we failed to get IPs but have cached ones (expired), return those as fallback
        // This prevents breaking the whitelist if CF is down
        if (empty($ips)) {
            $cached = get_transient(self::CACHE_KEY);
            if ($cached !== false && is_array($cached)) {
                return $cached;
            }
            // Fallback to hardcoded list (as of Jan 2026) if everything fails
            return $this->get_fallback_ips();
        }

        // Cache result
        set_transient(self::CACHE_KEY, $ips, self::CACHE_EXPIRY);

        return $ips;
    }

    /**
     * Fetch IPs from URL
     *
     * @param string $url URL to fetch
     * @return array List of IPs
     */
    private function fetch_ips($url) {
        $response = wp_remote_get($url, [
            'timeout' => 10,
            'sslverify' => true,
        ]);

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            // Log error
            $error = is_wp_error($response) ? $response->get_error_message() : 'HTTP ' . wp_remote_retrieve_response_code($response);
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
            error_log("VietShield: Failed to fetch Cloudflare IPs from {$url}: {$error}");
            return [];
        }

        $body = wp_remote_retrieve_body($response);
        if (empty($body)) {
            return [];
        }

        $ips = explode("\n", $body);
        $ips = array_map('trim', $ips);
        $ips = array_filter($ips, function($ip) {
            return !empty($ip) && (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) || strpos($ip, '/') !== false);
        });

        return array_values($ips);
    }

    /**
     * Get fallback IP ranges
     * 
     * @return array
     */
    private function get_fallback_ips() {
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
            '2c0f:f248::/32'
        ];
    }
}
