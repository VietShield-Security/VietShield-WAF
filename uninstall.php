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

$tables = [
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

foreach ($tables as $table) {
    $wpdb->query("DROP TABLE IF EXISTS $table");
}

// Clear scheduled cron jobs
wp_clear_scheduled_hook('vietshield_cleanup_logs');
wp_clear_scheduled_hook('vietshield_update_threat_feed');
wp_clear_scheduled_hook('vietshield_aggregate_stats');
wp_clear_scheduled_hook('vietshield_file_scan_event');
wp_clear_scheduled_hook('vietshield_malware_scan_event');
wp_clear_scheduled_hook('vietshield_threat_intel_sync');
wp_clear_scheduled_hook('vietshield_maintenance');
wp_clear_scheduled_hook('vietshield_submit_threats');
