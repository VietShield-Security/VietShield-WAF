<?php
/**
 * Plugin Deactivator
 * 
 * @package VietShield_WAF
 */

if (!defined('ABSPATH')) {
    exit;
}

class VietShield_Deactivator {
    
    /**
     * Deactivation tasks
     */
    public static function deactivate() {
        self::clear_cron_jobs();
        self::cleanup_temp_data();
        self::disable_early_blocking();
        
        // Flush rewrite rules
        flush_rewrite_rules();
    }
    
    /**
     * Disable early blocking (remove from .user.ini and .htaccess)
     */
    private static function disable_early_blocking() {
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-early-blocker.php';
        $early_blocker = new \VietShield\Firewall\EarlyBlocker();
        $early_blocker->disable();
    }
    
    /**
     * Clear scheduled cron jobs
     */
    private static function clear_cron_jobs() {
        wp_clear_scheduled_hook('vietshield_cleanup_logs');
        wp_clear_scheduled_hook('vietshield_update_threat_feed');
        wp_clear_scheduled_hook('vietshield_aggregate_stats');
        wp_clear_scheduled_hook('vietshield_file_scan_event');
        wp_clear_scheduled_hook('vietshield_malware_scan_event');
        wp_clear_scheduled_hook('vietshield_threat_intel_sync');
        wp_clear_scheduled_hook('vietshield_maintenance');
    }
    
    /**
     * Cleanup temporary data
     */
    private static function cleanup_temp_data() {
        global $wpdb;
        
        // Clear rate limit table (temporary data)
        $table = $wpdb->prefix . 'vietshield_rate_limits';
        $wpdb->query("TRUNCATE TABLE $table");
        
        // Clear expired temporary blocks
        $ip_table = $wpdb->prefix . 'vietshield_ip_lists';
        $wpdb->delete($ip_table, [
            'list_type' => 'temporary'
        ]);
    }
}
