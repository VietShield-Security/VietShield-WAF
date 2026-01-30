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
    

}
