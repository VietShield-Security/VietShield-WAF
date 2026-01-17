<?php
/**
 * Scheduled Tasks
 *
 * Handles all scheduled maintenance tasks for VietShield WAF.
 *
 * @package VietShield_WAF
 */

if (!defined('ABSPATH')) {
    exit;
}

class VietShield_Scheduled_Tasks {
    
    /**
     * Cleanup old logs
     */
    public static function cleanup_logs() {
        global $wpdb;
        
        $options = get_option('vietshield_options', []);
        $retention_days = absint($options['log_retention_days'] ?? 30);
        
        if ($retention_days <= 0) {
            return; // Keep all logs
        }
        
        $table = $wpdb->prefix . 'vietshield_logs';
        $cutoff_date = gmdate('Y-m-d H:i:s', strtotime("-{$retention_days} days"));
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Scheduled cleanup
        $deleted = $wpdb->query($wpdb->prepare(
            "DELETE FROM {$table} WHERE timestamp < %s",
            $cutoff_date
        ));
        
        if ($deleted > 0) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
            error_log(sprintf('VietShield: Cleaned up %d old log entries (older than %d days)', $deleted, $retention_days));
        }
        
        // Cleanup old rate limit entries (window_start is a timestamp)
        $rate_limit_table = $wpdb->prefix . 'vietshield_rate_limits';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Scheduled cleanup
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
        $wpdb->query("DELETE FROM {$rate_limit_table} WHERE window_start < UNIX_TIMESTAMP(NOW() - INTERVAL 1 HOUR)");
        
        // Cleanup old login attempts (keep only last 90 days)
        $login_table = $wpdb->prefix . 'vietshield_login_attempts';
        $login_cutoff = gmdate('Y-m-d H:i:s', strtotime('-90 days'));
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Scheduled cleanup
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
        $wpdb->query($wpdb->prepare(
            "DELETE FROM {$login_table} WHERE timestamp < %s",
            $login_cutoff
        ));
    }
    
    /**
     * Aggregate statistics
     */
    public static function aggregate_stats() {
        global $wpdb;
        
        $logs_table = $wpdb->prefix . 'vietshield_logs';
        $stats_table = $wpdb->prefix . 'vietshield_stats';
        
        // Process current and previous hour to ensure no data loss
        // Use WP local time to match log timestamps
        $current_ts = current_time('timestamp');
        $timestamps = [$current_ts, $current_ts - 3600];
        
        foreach ($timestamps as $ts) {
            $date = gmdate('Y-m-d', $ts);
            $hour = gmdate('H', $ts);
            
            // Aggregate hourly stats
            // Note: total_requests is now incremented real-time via increment_total_requests()
            // so we only aggregate attack stats from logs table
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Aggregation query
            $hourly_stats = $wpdb->get_row($wpdb->prepare(
                "SELECT 
                    SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) as blocked,
                    SUM(CASE WHEN action = 'rate_limited' THEN 1 ELSE 0 END) as rate_limited,
                    SUM(CASE WHEN action = 'threat_intelligence' THEN 1 ELSE 0 END) as threat_intel,
                    SUM(CASE WHEN attack_type = 'sqli' THEN 1 ELSE 0 END) as sqli,
                    SUM(CASE WHEN attack_type = 'xss' THEN 1 ELSE 0 END) as xss,
                    SUM(CASE WHEN attack_type = 'rce' THEN 1 ELSE 0 END) as rce,
                    SUM(CASE WHEN attack_type = 'lfi' THEN 1 ELSE 0 END) as lfi,
                    SUM(CASE WHEN attack_type = 'bad_bot' THEN 1 ELSE 0 END) as bad_bot
                FROM {$logs_table}
                WHERE DATE(timestamp) = %s AND HOUR(timestamp) = %s",
                $date,
                $hour
            ), ARRAY_A);
            
            // Get current total_requests from stats table (already incremented real-time)
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Aggregation query
            $current_stats = $wpdb->get_row($wpdb->prepare(
                "SELECT total_requests FROM {$stats_table}
                 WHERE date = %s AND hour = %s",
                $date,
                $hour
            ), ARRAY_A);
            
            $total_requests = isset($current_stats['total_requests']) ? (int) $current_stats['total_requests'] : 0;
            
            if ($hourly_stats && (
                ($hourly_stats['blocked'] ?? 0) > 0 ||
                ($hourly_stats['rate_limited'] ?? 0) > 0 ||
                ($hourly_stats['threat_intel'] ?? 0) > 0 ||
                ($hourly_stats['sqli'] ?? 0) > 0 ||
                ($hourly_stats['xss'] ?? 0) > 0 ||
                ($hourly_stats['rce'] ?? 0) > 0 ||
                ($hourly_stats['lfi'] ?? 0) > 0 ||
                ($hourly_stats['bad_bot'] ?? 0) > 0
            )) {
                // Insert or update stats (preserve total_requests from real-time increments)
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Aggregation update
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
                $wpdb->replace($stats_table, [
                    'date' => $date,
                    'hour' => $hour,
                    'total_requests' => $total_requests, // Preserve real-time count
                    'blocked' => (int) ($hourly_stats['blocked'] ?? 0),
                    'rate_limited' => (int) ($hourly_stats['rate_limited'] ?? 0),
                    'threat_intel' => (int) ($hourly_stats['threat_intel'] ?? 0),
                    'sqli' => (int) ($hourly_stats['sqli'] ?? 0),
                    'xss' => (int) ($hourly_stats['xss'] ?? 0),
                    'rce' => (int) ($hourly_stats['rce'] ?? 0),
                    'lfi' => (int) ($hourly_stats['lfi'] ?? 0),
                    'bad_bot' => (int) ($hourly_stats['bad_bot'] ?? 0),
                    'updated_at' => current_time('mysql'),
                ], [
                    '%s', '%d', '%d', '%d', '%d', '%d', '%d', '%d', '%d', '%d', '%d', '%s'
                ]);
            } elseif ($total_requests > 0) {
                // Even if no attacks, ensure stats row exists with total_requests
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Aggregation update
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
                $wpdb->replace($stats_table, [
                    'date' => $date,
                    'hour' => $hour,
                    'total_requests' => $total_requests,
                    'blocked' => 0,
                    'rate_limited' => 0,
                    'threat_intel' => 0,
                    'sqli' => 0,
                    'xss' => 0,
                    'rce' => 0,
                    'lfi' => 0,
                    'bad_bot' => 0,
                    'updated_at' => current_time('mysql'),
                ], [
                    '%s', '%d', '%d', '%d', '%d', '%d', '%d', '%d', '%d', '%d', '%d', '%s'
                ]);
            }
        }
        
        // Cleanup old stats (keep only last 90 days)
        $stats_cutoff = gmdate('Y-m-d', strtotime('-90 days'));
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Scheduled cleanup
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
        $wpdb->query($wpdb->prepare(
            "DELETE FROM {$stats_table} WHERE date < %s",
            $stats_cutoff
        ));
    }
    
    /**
     * Update threat feed (legacy - now handled by ThreatIntelligence)
     * This is kept for backward compatibility
     */
    public static function update_threat_feed() {
        // This is now handled by ThreatIntelligence::cron_sync()
        // Keep this method for backward compatibility but it does nothing
        return;
    }
    
    /**
     * Maintenance tasks
     */
    public static function maintenance() {
        global $wpdb;
        
        // 1. Optimize database tables
        $tables = [
            $wpdb->prefix . 'vietshield_logs',
            $wpdb->prefix . 'vietshield_ip_lists',
            $wpdb->prefix . 'vietshield_rate_limits',
            $wpdb->prefix . 'vietshield_stats',
            $wpdb->prefix . 'vietshield_login_attempts',
            $wpdb->prefix . 'vietshield_threat_intel',
            $wpdb->prefix . 'vietshield_threats_queue',
        ];
        
        foreach ($tables as $table) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Maintenance optimization
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
            $wpdb->query("OPTIMIZE TABLE {$table}");
        }
        
        // 2. Cleanup expired temporary IP blocks
        $ip_table = $wpdb->prefix . 'vietshield_ip_lists';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Maintenance cleanup
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
        $wpdb->query("DELETE FROM {$ip_table} WHERE list_type = 'temporary' AND expires_at < NOW()");
        
        // 2.5. Cleanup old threats queue entries (older than 30 days)
        require_once VIETSHIELD_PLUGIN_DIR . 'includes/firewall/class-threats-sharing.php';
        \VietShield\Firewall\ThreatsSharing::cleanup_old_entries();
        
        // 3. Cleanup old scan results (keep only last 10 scans per type)
        $file_scans_table = $wpdb->prefix . 'vietshield_file_scans';
        $malware_scans_table = $wpdb->prefix . 'vietshield_malware_scans';
        
        // Keep only last 10 file scans
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Maintenance cleanup
        $old_file_scans = $wpdb->get_col("SELECT id FROM {$file_scans_table} ORDER BY id DESC LIMIT 10, 999999");
        if (!empty($old_file_scans)) {
            $ids = implode(',', array_map('intval', $old_file_scans));
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- IDs are intval-sanitized
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
            $wpdb->query("DELETE FROM {$file_scans_table} WHERE id IN ({$ids})");
            $items_table = $wpdb->prefix . 'vietshield_file_scan_items';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- IDs are intval-sanitized
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
            $wpdb->query("DELETE FROM {$items_table} WHERE scan_id IN ({$ids})");
        }
        
        // Keep only last 10 malware scans
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Maintenance cleanup
        $old_malware_scans = $wpdb->get_col("SELECT id FROM {$malware_scans_table} ORDER BY id DESC LIMIT 10, 999999");
        if (!empty($old_malware_scans)) {
            $ids = implode(',', array_map('intval', $old_malware_scans));
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- IDs are intval-sanitized
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
            $wpdb->query("DELETE FROM {$malware_scans_table} WHERE id IN ({$ids})");
            $items_table = $wpdb->prefix . 'vietshield_malware_scan_items';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- IDs are intval-sanitized
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
            $wpdb->query("DELETE FROM {$items_table} WHERE scan_id IN ({$ids})");
        }
        
        // 4. Clear expired transients
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Transient cleanup
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_vietshield_%' AND option_value < UNIX_TIMESTAMP()");
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Transient cleanup
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_vietshield_%' AND option_value < UNIX_TIMESTAMP()");
        
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WAF debug logging
        error_log('VietShield: Maintenance tasks completed');
    }
}
