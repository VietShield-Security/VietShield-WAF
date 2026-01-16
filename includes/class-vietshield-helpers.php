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
        $options = get_option('vietshield_options', []);
        $timezone = $options['log_timezone'] ?? get_option('timezone_string') ?: 'UTC';
        
        try {
            $dt = new \DateTime($timestamp, new \DateTimeZone('UTC'));
            $dt->setTimezone(new \DateTimeZone($timezone));
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
        $options = get_option('vietshield_options', []);
        $timezone = $options['log_timezone'] ?? get_option('timezone_string') ?: 'UTC';
        
        try {
            $dt = new \DateTime($utc_timestamp, new \DateTimeZone('UTC'));
            $dt->setTimezone(new \DateTimeZone($timezone));
            return $dt->format('Y-m-d H:i:s');
        } catch (\Exception $e) {
            return $utc_timestamp;
        }
    }
    
    /**
     * Get all available timezones
     * 
     * @return array Timezone identifier => Display name
     */
    public static function get_timezones() {
        $timezones = [];
        $identifiers = timezone_identifiers_list();
        
        foreach ($identifiers as $tz) {
            try {
                $dt = new \DateTime('now', new \DateTimeZone($tz));
                $offset = $dt->getOffset();
                $hours = intval($offset / 3600);
                $minutes = abs(intval(($offset % 3600) / 60));
                $sign = $hours >= 0 ? '+' : '-';
                $offset_str = sprintf('%s%02d:%02d', $sign, abs($hours), $minutes);
                
                $timezones[$tz] = $tz . ' (GMT' . $offset_str . ')';
            } catch (\Exception $e) {
                // Skip invalid timezones
            }
        }
        
        return $timezones;
    }
    
    /**
     * Get timezone groups (by region)
     * 
     * @return array
     */
    public static function get_timezone_groups() {
        $groups = [
            'Asia' => [],
            'Europe' => [],
            'America' => [],
            'Africa' => [],
            'Australia' => [],
            'Pacific' => [],
            'Atlantic' => [],
            'Indian' => [],
            'Antarctica' => [],
            'Arctic' => [],
            'UTC' => [],
        ];
        
        $identifiers = timezone_identifiers_list();
        
        foreach ($identifiers as $tz) {
            $parts = explode('/', $tz, 2);
            $region = $parts[0] ?? 'UTC';
            
            if (isset($groups[$region])) {
                try {
                    $dt = new \DateTime('now', new \DateTimeZone($tz));
                    $offset = $dt->getOffset();
                    $hours = intval($offset / 3600);
                    $minutes = abs(intval(($offset % 3600) / 60));
                    $sign = $hours >= 0 ? '+' : '-';
                    $offset_str = sprintf('%s%02d:%02d', $sign, abs($hours), $minutes);
                    
                    $groups[$region][$tz] = str_replace('_', ' ', $parts[1] ?? $tz) . ' (GMT' . $offset_str . ')';
                } catch (\Exception $e) {
                    // Skip
                }
            }
        }
        
        // Add UTC
        $groups['UTC']['UTC'] = 'UTC (GMT+00:00)';
        
        return $groups;
    }
}
