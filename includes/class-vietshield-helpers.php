<?php
/**
 * Helper Functions
 * 
 * @package VietShield_WAF
 */

if (!defined('ABSPATH')) {
    exit;
}

class VietShield_Helpers {
    
    /**
     * Format timestamp according to configured timezone
     * 
     * @param string $timestamp MySQL timestamp or Unix timestamp
     * @param string $format Date format (default: 'Y-m-d H:i:s')
     * @return string Formatted date
     */
    public static function format_timestamp($timestamp, $format = 'Y-m-d H:i:s') {
        try {
            $dt = new \DateTime($timestamp, new \DateTimeZone('UTC'));
            // Use WordPress native timezone
            $dt->setTimezone(wp_timezone());
            return $dt->format($format);
        } catch (\Exception $e) {
            // Fallback to original timestamp
            return $timestamp;
        }
    }
    
    /**
     * Get current timestamp in UTC (for database storage)
     * 
     * @return string MySQL formatted timestamp in UTC
     */
    public static function get_current_timestamp() {
        try {
            $dt = new \DateTime('now', new \DateTimeZone('UTC'));
            return $dt->format('Y-m-d H:i:s');
        } catch (\Exception $e) {
            return gmdate('Y-m-d H:i:s');
        }
    }
    
    /**
     * Convert UTC timestamp to configured timezone
     * 
     * @param string $utc_timestamp MySQL timestamp in UTC
     * @return string MySQL timestamp in configured timezone
     */
    public static function convert_to_timezone($utc_timestamp) {
        try {
            $dt = new \DateTime($utc_timestamp, new \DateTimeZone('UTC'));
            // Use WordPress native timezone
            $dt->setTimezone(wp_timezone());
            return $dt->format('Y-m-d H:i:s');
        } catch (\Exception $e) {
            return $utc_timestamp;
        }
    }

    /**
     * Get cache directory for block pages
     */
    public static function get_block_cache_dir() {
        return WP_CONTENT_DIR . '/cache/vietshield/';
    }

    /**
     * Send a cached or freshly rendered 403 block page
     *
     * Renders the block page template once per block_id and caches the HTML
     * as a static file. Subsequent requests with the same block_id serve the
     * cached file directly, skipping template rendering and option lookups.
     *
     * @param string $block_type  Identifier for the block type (e.g. 'HIDE_LOGIN', 'ADMIN_ACCESS')
     * @param string $client_ip   The client IP address
     * @param string $message     The block message to display
     */
    public static function send_blocked_response($block_type, $client_ip, $message) {
        $block_id = strtoupper(substr(md5($client_ip . $block_type . gmdate('Y-m-d')), 0, 12));

        $cache_dir = self::get_block_cache_dir();
        $cache_file = $cache_dir . $block_id . '.html';

        // Try to serve cached version first
        if (file_exists($cache_file)) {
            // Verify cache is from today (block_id changes daily, but extra safety)
            $cache_age = time() - filemtime($cache_file);
            if ($cache_age < 86400) { // Less than 24 hours old
                status_header(403);
                nocache_headers();
                header('Content-Type: text/html; charset=utf-8');
                header('X-VietShield-Cache: HIT');
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_readfile
                readfile($cache_file);
                exit;
            }
            // Stale cache, remove it
            // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
            @unlink($cache_file);
        }

        // Render and cache the block page
        status_header(403);
        nocache_headers();
        header('Content-Type: text/html; charset=utf-8');
        header('X-VietShield-Cache: MISS');

        $block_page = VIETSHIELD_PLUGIN_DIR . 'templates/block-page.php';

        if (file_exists($block_page)) {
            $status = 403;
            $accent_color = '#e74c3c';
            $options = get_option('vietshield_options', []);
            $tz_string = $options['log_timezone'] ?? 'UTC';
            $timezone_label = $tz_string;
            try {
                $tz = new \DateTimeZone($tz_string);
                $current_time = (new \DateTime('now', $tz))->format('Y-m-d H:i:s');
            } catch (\Exception $e) {
                $current_time = gmdate('Y-m-d H:i:s');
                $timezone_label = 'UTC';
            }

            // Capture output for caching
            ob_start();
            include $block_page;
            $html = ob_get_clean();

            // Save to cache
            if (!is_dir($cache_dir)) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir
                @mkdir($cache_dir, 0755, true);
            }
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
            @file_put_contents($cache_file, $html, LOCK_EX);

            echo $html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Already escaped in template
        } else {
            echo '<!DOCTYPE html><html><head><title>403 Forbidden</title></head>';
            echo '<body><h1>403 Forbidden</h1><p>Access denied.</p></body></html>';
        }

        exit;
    }

    /**
     * Clean up expired block page cache files (older than 24 hours)
     */
    public static function cleanup_block_cache() {
        $cache_dir = self::get_block_cache_dir();

        if (!is_dir($cache_dir)) {
            return;
        }

        $files = glob($cache_dir . '*.html');
        if (empty($files)) {
            return;
        }

        $now = time();
        foreach ($files as $file) {
            if (($now - filemtime($file)) > 86400) {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
                @unlink($file);
            }
        }
    }
}
