<?php
/**
 * VietShield WAF Uninstall
 * 
 * Cleanup when plugin is uninstalled
 */

// Exit if not called by WordPress
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Remove all options
delete_option('vietshield_options');
delete_option('vietshield_db_version');
delete_option('vietshield_wizard_completed');
delete_option('vietshield_threat_intel_last_sync');
delete_option('vietshield_threat_intel_sync_count');
delete_option('vietshield_threat_intel_sync_category');

// Remove wizard step options
delete_option('vietshield_wizard_step_1');
delete_option('vietshield_wizard_step_2');
delete_option('vietshield_wizard_step_3');

// Remove transients
delete_transient('vietshield_activated');
delete_transient('vietshield_show_wizard');
delete_transient('vietshield_force_wizard_redirect');
delete_transient('vietshield_wizard_should_load');
delete_transient('vietshield_threat_intel_syncing');
delete_transient('vietshield_threat_intel_syncing_initial');

// Remove database tables
global $wpdb;

// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Uninstall file, variables are local
$vietshield_tables = [
    $wpdb->prefix . 'vietshield_logs',
    $wpdb->prefix . 'vietshield_ip_lists',
    $wpdb->prefix . 'vietshield_rate_limits',
    $wpdb->prefix . 'vietshield_stats',
    $wpdb->prefix . 'vietshield_login_attempts',
    $wpdb->prefix . 'vietshield_file_scans',
    $wpdb->prefix . 'vietshield_file_scan_items',
    $wpdb->prefix . 'vietshield_malware_scans',
    $wpdb->prefix . 'vietshield_malware_scan_items',
    $wpdb->prefix . 'vietshield_threat_intel',
    $wpdb->prefix . 'vietshield_threats_queue',
];

foreach ($vietshield_tables as $vietshield_table) {
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Uninstall cleanup
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- WAF performance
    $wpdb->query("DROP TABLE IF EXISTS $vietshield_table");
}

// Disable early blocker (remove from .user.ini/.htaccess) and clean up generated files
$blocker_file = WP_CONTENT_DIR . '/vietshield-blocker.php';
$blocked_ips_file = WP_CONTENT_DIR . '/vietshield-blocked-ips.php';
$blocked_ips_bin = WP_CONTENT_DIR . '/vietshield-blocked-ips.bin';

// Remove auto_prepend_file from .user.ini
$user_ini = ABSPATH . '.user.ini';
if (file_exists($user_ini) && is_writable($user_ini)) {
    $content = file_get_contents($user_ini);
    if ($content !== false && strpos($content, 'vietshield') !== false) {
        $content = preg_replace('/^.*vietshield.*$/m', '', $content);
        $content = preg_replace('/\n{3,}/', "\n\n", trim($content));
        file_put_contents($user_ini, $content);
    }
}

// Delete generated blocker files
foreach ([$blocker_file, $blocked_ips_file, $blocked_ips_bin] as $file) {
    if (file_exists($file)) {
        @unlink($file);
    }
}

// Clear ALL scheduled cron jobs (including previously missing ones)
wp_clear_scheduled_hook('vietshield_cleanup_logs');
wp_clear_scheduled_hook('vietshield_update_threat_feed');
wp_clear_scheduled_hook('vietshield_aggregate_stats');
wp_clear_scheduled_hook('vietshield_file_scan_event');
wp_clear_scheduled_hook('vietshield_malware_scan_event');
wp_clear_scheduled_hook('vietshield_threat_intel_sync');
wp_clear_scheduled_hook('vietshield_maintenance');
wp_clear_scheduled_hook('vietshield_submit_threats');
wp_clear_scheduled_hook('vietshield_ip_whitelist_sync');
wp_clear_scheduled_hook('vietshield_sync_ip_metadata');
wp_clear_scheduled_hook('vietshield_threat_intel_initial_sync');
wp_clear_scheduled_hook('vietshield_early_blocker_setup');

// Clean up additional transients and options
delete_transient('vietshield_github_release');
delete_option('vietshield_site_key');
